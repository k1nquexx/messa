using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Messa.Core.Models;
using Messa.Core.Crypto;

namespace Messa.Server
{
    class Program
    {
        private static readonly int Port = 8080;
        private static readonly ConcurrentDictionary<string, WebSocket> ConnectedClients = new();
        private static readonly string DataDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data");
        private static readonly string DeadDropFile = Path.Combine(DataDir, "deaddrop.json");
        private static readonly string KeyDirFile = Path.Combine(DataDir, "key_directory.json");
        private static readonly string TunnelFile = Path.Combine(DataDir, "tunnel.json");

        // Key Directory & Pre-Key Bundles
        private static readonly ConcurrentDictionary<string, PreKeyBundle> BundlesByFingerprint = new();
        private static readonly ConcurrentDictionary<string, string> FingerprintByUsername = new(StringComparer.OrdinalIgnoreCase);

        // Offline Dead-Drop queue
        private static readonly ConcurrentDictionary<string, List<ProtocolPacket>> OfflineQueue = new();
        private static Process? _cloudflaredProcess;

        static async Task Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.Title = "MESSA - Sovereign Relay Server (C# / .NET)";

            PrintBanner();

            Directory.CreateDirectory(DataDir);
            LoadKeyDirectory();
            LoadOfflineQueue();

            StartCloudflareTunnel();

            var httpListener = new HttpListener();
            try
            {
                httpListener.Prefixes.Add($"http://*:{Port}/");
                httpListener.Start();
                LogSuccess($"WebSocket Relay listening on ws://0.0.0.0:{Port}/");
            }
            catch
            {
                httpListener.Close();
                httpListener = new HttpListener();
                httpListener.Prefixes.Add($"http://localhost:{Port}/");
                httpListener.Prefixes.Add($"http://127.0.0.1:{Port}/");
                httpListener.Start();
                LogSuccess($"WebSocket Relay listening on ws://127.0.0.1:{Port}/");
            }

            AppDomain.CurrentDomain.ProcessExit += (s, e) => StopCloudflareTunnel();

            LogInfo("Server is operational. Waiting for client connections...");

            while (true)
            {
                try
                {
                    var context = await httpListener.GetContextAsync();
                    if (context.Request.IsWebSocketRequest)
                    {
                        _ = ProcessWebSocketRequestAsync(context);
                    }
                    else
                    {
                        var resp = Encoding.UTF8.GetBytes("{\"status\":\"ok\",\"service\":\"MESSA Sovereign Relay Server\"}");
                        context.Response.ContentType = "application/json";
                        context.Response.ContentLength64 = resp.Length;
                        await context.Response.OutputStream.WriteAsync(resp);
                        context.Response.Close();
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Listener error: {ex.Message}");
                }
            }
        }

        private static async Task ProcessWebSocketRequestAsync(HttpListenerContext context)
        {
            HttpListenerWebSocketContext webSocketContext;
            try
            {
                webSocketContext = await context.AcceptWebSocketAsync(subProtocol: null);
            }
            catch (Exception ex)
            {
                context.Response.StatusCode = 500;
                context.Response.Close();
                LogError($"WebSocket handshake failed: {ex.Message}");
                return;
            }

            var webSocket = webSocketContext.WebSocket;
            string? clientFingerprint = null;
            var buffer = new byte[1024 * 64];

            try
            {
                while (webSocket.State == WebSocketState.Open)
                {
                    using var ms = new MemoryStream();
                    WebSocketReceiveResult result;
                    do
                    {
                        result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
                        if (result.MessageType == WebSocketMessageType.Close)
                        {
                            await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", CancellationToken.None);
                            return;
                        }
                        ms.Write(buffer, 0, result.Count);
                    } while (!result.EndOfMessage);

                    var messageJson = Encoding.UTF8.GetString(ms.ToArray());
                    var packet = JsonSerializer.Deserialize<ProtocolPacket>(messageJson);
                    if (packet == null) continue;

                    switch (packet.Type)
                    {
                        case "register":
                            if (!string.IsNullOrEmpty(packet.Fingerprint))
                            {
                                clientFingerprint = packet.Fingerprint;
                                ConnectedClients[clientFingerprint] = webSocket;
                                LogSuccess($"Client registered: {clientFingerprint[..Math.Min(16, clientFingerprint.Length)]}...");
                                await DeliverOfflineMessagesAsync(clientFingerprint, webSocket);
                            }
                            break;

                        case "publish_bundle":
                            if (packet.Bundle != null)
                            {
                                if (packet.Bundle.Verify())
                                {
                                    BundlesByFingerprint[packet.Bundle.Fingerprint] = packet.Bundle;
                                    if (!string.IsNullOrEmpty(packet.Bundle.Username))
                                    {
                                        FingerprintByUsername[packet.Bundle.Username] = packet.Bundle.Fingerprint;
                                    }
                                    SaveKeyDirectory();
                                    LogSuccess($"[KEY-DIR] Published signed PreKey bundle for @{packet.Bundle.Username} ({packet.Bundle.Fingerprint[..8]}...)");
                                    await SendJsonAsync(webSocket, new ProtocolPacket { Type = "status", Status = "bundle_published" });
                                }
                                else
                                {
                                    LogWarn("[KEY-DIR] Rejected invalid PreKey bundle signature!");
                                    await SendJsonAsync(webSocket, new ProtocolPacket { Type = "error", Error = "Invalid bundle signature" });
                                }
                            }
                            break;

                        case "lookup_bundle":
                            if (!string.IsNullOrEmpty(packet.Query))
                            {
                                var query = packet.Query.Trim().TrimStart('@');
                                PreKeyBundle? foundBundle = null;

                                if (BundlesByFingerprint.TryGetValue(query, out var b1))
                                {
                                    foundBundle = b1;
                                }
                                else if (FingerprintByUsername.TryGetValue(query, out var fp) && BundlesByFingerprint.TryGetValue(fp, out var b2))
                                {
                                    foundBundle = b2;
                                }

                                if (foundBundle != null)
                                {
                                    await SendJsonAsync(webSocket, new ProtocolPacket { Type = "bundle_result", Bundle = foundBundle });
                                    LogInfo($"[KEY-DIR] Lookup success for query: {query}");
                                }
                                else
                                {
                                    await SendJsonAsync(webSocket, new ProtocolPacket { Type = "error", Error = "User not found in Key Directory" });
                                    LogWarn($"[KEY-DIR] User not found for query: {query}");
                                }
                            }
                            break;

                        case "ratchet_message":
                            if (packet.RatchetMessage != null && !string.IsNullOrEmpty(packet.RatchetMessage.RecipientFingerprint))
                            {
                                var recipient = packet.RatchetMessage.RecipientFingerprint;
                                if (ConnectedClients.TryGetValue(recipient, out var recipientSocket) && recipientSocket.State == WebSocketState.Open)
                                {
                                    await SendJsonAsync(recipientSocket, packet);
                                    await SendJsonAsync(webSocket, new ProtocolPacket { Type = "status", Status = "delivered" });
                                    LogInfo($"Relayed Double Ratchet message to online recipient: {recipient[..8]}...");
                                }
                                else
                                {
                                    EnqueueOfflineMessage(recipient, packet);
                                    await SendJsonAsync(webSocket, new ProtocolPacket { Type = "status", Status = "queued_offline" });
                                    LogWarn($"Recipient {recipient[..8]}... is offline. Saved to Dead-Drop.");
                                }
                            }
                            break;

                        case "ping":
                            await SendJsonAsync(webSocket, new ProtocolPacket { Type = "pong" });
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                LogWarn($"Client disconnected ({ex.Message})");
            }
            finally
            {
                if (!string.IsNullOrEmpty(clientFingerprint))
                {
                    ConnectedClients.TryRemove(clientFingerprint, out _);
                }
                webSocket.Dispose();
            }
        }

        private static async Task SendJsonAsync(WebSocket socket, ProtocolPacket packet)
        {
            if (socket.State != WebSocketState.Open) return;
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(packet));
            await socket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, CancellationToken.None);
        }

        private static void EnqueueOfflineMessage(string recipient, ProtocolPacket packet)
        {
            OfflineQueue.AddOrUpdate(recipient,
                _ => new List<ProtocolPacket> { packet },
                (_, list) => { lock (list) { list.Add(packet); } return list; });
            SaveOfflineQueue();
        }

        private static async Task DeliverOfflineMessagesAsync(string recipient, WebSocket socket)
        {
            if (OfflineQueue.TryRemove(recipient, out var list))
            {
                List<ProtocolPacket> copy;
                lock (list) copy = new List<ProtocolPacket>(list);

                foreach (var p in copy)
                {
                    await SendJsonAsync(socket, p);
                }
                SaveOfflineQueue();
            }
        }

        private static void LoadKeyDirectory()
        {
            if (File.Exists(KeyDirFile))
            {
                try
                {
                    var data = JsonSerializer.Deserialize<Dictionary<string, PreKeyBundle>>(File.ReadAllText(KeyDirFile));
                    if (data != null)
                    {
                        foreach (var kvp in data)
                        {
                            BundlesByFingerprint[kvp.Key] = kvp.Value;
                            if (!string.IsNullOrEmpty(kvp.Value.Username))
                            {
                                FingerprintByUsername[kvp.Value.Username] = kvp.Key;
                            }
                        }
                        LogInfo($"[KEY-DIR] Loaded {BundlesByFingerprint.Count} PreKey bundle(s) from disk.");
                    }
                }
                catch { }
            }
        }

        private static void SaveKeyDirectory()
        {
            try
            {
                var dict = new Dictionary<string, PreKeyBundle>(BundlesByFingerprint);
                File.WriteAllText(KeyDirFile, JsonSerializer.Serialize(dict, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        private static void LoadOfflineQueue()
        {
            if (File.Exists(DeadDropFile))
            {
                try
                {
                    var data = JsonSerializer.Deserialize<Dictionary<string, List<ProtocolPacket>>>(File.ReadAllText(DeadDropFile));
                    if (data != null)
                        foreach (var kvp in data) OfflineQueue[kvp.Key] = kvp.Value;
                }
                catch { }
            }
        }

        private static void SaveOfflineQueue()
        {
            try
            {
                var dict = new Dictionary<string, List<ProtocolPacket>>(OfflineQueue);
                File.WriteAllText(DeadDropFile, JsonSerializer.Serialize(dict, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        private static void StartCloudflareTunnel()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = @"C:\Program Files (x86)\cloudflared\cloudflared.exe",
                    Arguments = $"tunnel --url http://127.0.0.1:{Port}",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                _cloudflaredProcess = new Process { StartInfo = psi };
                _cloudflaredProcess.ErrorDataReceived += (s, e) =>
                {
                    if (string.IsNullOrEmpty(e.Data)) return;
                    var match = Regex.Match(e.Data, @"https://[a-zA-Z0-9-]+\.trycloudflare\.com");
                    if (match.Success)
                    {
                        var wssUrl = match.Value.Replace("https://", "wss://");
                        LogSuccess($"[CLOUDFLARE TUNNEL ONLINE] Relay: {wssUrl}");
                        File.WriteAllText(TunnelFile, JsonSerializer.Serialize(new { url = wssUrl, lanUrl = $"ws://127.0.0.1:{Port}" }));
                    }
                };
                _cloudflaredProcess.Start();
                _cloudflaredProcess.BeginErrorReadLine();
            }
            catch { }
        }

        private static void StopCloudflareTunnel()
        {
            try { _cloudflaredProcess?.Kill(true); } catch { }
        }

        private static void PrintBanner() => Console.WriteLine("\n[MESSA] Sovereign Native C# Relay Server (with Key Directory & Double Ratchet)\n");
        private static void LogInfo(string m) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [INFO] {m}");
        private static void LogSuccess(string m) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [OK] {m}");
        private static void LogWarn(string m) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [WARN] {m}");
        private static void LogError(string m) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [ERROR] {m}");
    }
}
