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
        private static readonly string TunnelFile = Path.Combine(DataDir, "tunnel.json");
        private static readonly ConcurrentDictionary<string, List<EncryptedEnvelope>> OfflineQueue = new();
        private static Process? _cloudflaredProcess;

        static async Task Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.Title = "MESSA - Sovereign Relay Server (C# / .NET)";

            PrintBanner();

            Directory.CreateDirectory(DataDir);
            LoadOfflineQueue();

            // Start Cloudflare Tunnel if available
            StartCloudflareTunnel();

            // Start WebSocket Server via HttpListener
            var httpListener = new HttpListener();
            var prefix = $"http://*:{Port}/";
            try
            {
                httpListener.Prefixes.Add(prefix);
                httpListener.Start();
                LogSuccess($"WebSocket Relay listening on ws://0.0.0.0:{Port}/");
            }
            catch (Exception ex)
            {
                LogWarn($"Failed to bind wildcard prefix ({ex.Message}), falling back to localhost...");
                httpListener.Close();
                httpListener = new HttpListener();
                httpListener.Prefixes.Add($"http://localhost:{Port}/");
                httpListener.Prefixes.Add($"http://127.0.0.1:{Port}/");
                httpListener.Start();
                LogSuccess($"WebSocket Relay listening on ws://127.0.0.1:{Port}/");
            }

            AppDomain.CurrentDomain.ProcessExit += (s, e) =>
            {
                StopCloudflareTunnel();
            };

            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                StopCloudflareTunnel();
                Environment.Exit(0);
            };

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
                        // Simple HTTP status endpoint
                        var responseBytes = Encoding.UTF8.GetBytes("{\"status\":\"ok\",\"service\":\"MESSA Sovereign Relay Server\"}");
                        context.Response.ContentType = "application/json";
                        context.Response.ContentLength64 = responseBytes.Length;
                        await context.Response.OutputStream.WriteAsync(responseBytes);
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

            var buffer = new byte[1024 * 64]; // 64 KB buffer

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

                                // Flush dead-drop queue for this client
                                await DeliverOfflineMessagesAsync(clientFingerprint, webSocket);
                            }
                            break;

                        case "send":
                            if (packet.Envelope != null && !string.IsNullOrEmpty(packet.Envelope.RecipientFingerprint))
                            {
                                var recipient = packet.Envelope.RecipientFingerprint;
                                if (ConnectedClients.TryGetValue(recipient, out var recipientSocket) && recipientSocket.State == WebSocketState.Open)
                                {
                                    // Deliver directly
                                    var outgoingPacket = new ProtocolPacket
                                    {
                                        Type = "message",
                                        Envelope = packet.Envelope
                                    };
                                    await SendJsonAsync(recipientSocket, outgoingPacket);
                                    LogInfo($"Relayed message to online recipient: {recipient[..Math.Min(16, recipient.Length)]}...");

                                    await SendJsonAsync(webSocket, new ProtocolPacket { Type = "status", Status = "delivered" });
                                }
                                else
                                {
                                    // Store in dead-drop queue
                                    EnqueueOfflineMessage(recipient, packet.Envelope);
                                    LogWarn($"Recipient {recipient[..Math.Min(16, recipient.Length)]}... is offline. Queued in Dead-Drop.");

                                    await SendJsonAsync(webSocket, new ProtocolPacket { Type = "status", Status = "queued_offline" });
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
                    LogInfo($"Client unregistered: {clientFingerprint[..Math.Min(16, clientFingerprint.Length)]}...");
                }
                webSocket.Dispose();
            }
        }

        private static async Task SendJsonAsync(WebSocket socket, ProtocolPacket packet)
        {
            if (socket.State != WebSocketState.Open) return;
            var json = JsonSerializer.Serialize(packet);
            var bytes = Encoding.UTF8.GetBytes(json);
            await socket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, CancellationToken.None);
        }

        private static void EnqueueOfflineMessage(string recipientFingerprint, EncryptedEnvelope envelope)
        {
            OfflineQueue.AddOrUpdate(recipientFingerprint,
                _ => new List<EncryptedEnvelope> { envelope },
                (_, list) => { lock (list) { list.Add(envelope); } return list; });

            SaveOfflineQueue();
        }

        private static async Task DeliverOfflineMessagesAsync(string recipientFingerprint, WebSocket socket)
        {
            if (OfflineQueue.TryRemove(recipientFingerprint, out var list))
            {
                List<EncryptedEnvelope> copy;
                lock (list)
                {
                    copy = new List<EncryptedEnvelope>(list);
                }

                LogInfo($"Flushing {copy.Count} offline message(s) for client...");
                foreach (var env in copy)
                {
                    var packet = new ProtocolPacket
                    {
                        Type = "message",
                        Envelope = env
                    };
                    await SendJsonAsync(socket, packet);
                }
                SaveOfflineQueue();
            }
        }

        private static void LoadOfflineQueue()
        {
            if (File.Exists(DeadDropFile))
            {
                try
                {
                    var json = File.ReadAllText(DeadDropFile);
                    var data = JsonSerializer.Deserialize<Dictionary<string, List<EncryptedEnvelope>>>(json);
                    if (data != null)
                    {
                        foreach (var kvp in data)
                        {
                            OfflineQueue[kvp.Key] = kvp.Value;
                        }
                        LogInfo($"Loaded {OfflineQueue.Count} queued recipient mailbox(es) from Dead-Drop.");
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Failed to load Dead-Drop file: {ex.Message}");
                }
            }
        }

        private static void SaveOfflineQueue()
        {
            try
            {
                var dict = new Dictionary<string, List<EncryptedEnvelope>>(OfflineQueue);
                var json = JsonSerializer.Serialize(dict, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(DeadDropFile, json);
            }
            catch (Exception ex)
            {
                LogError($"Failed to save Dead-Drop: {ex.Message}");
            }
        }

        private static void StartCloudflareTunnel()
        {
            var cfPaths = new[]
            {
                "cloudflared",
                @"C:\Program Files (x86)\cloudflared\cloudflared.exe",
                @"C:\Program Files\cloudflared\cloudflared.exe"
            };

            string? cfExecutable = null;
            foreach (var p in cfPaths)
            {
                if (File.Exists(p) || p == "cloudflared")
                {
                    cfExecutable = p;
                    break;
                }
            }

            if (string.IsNullOrEmpty(cfExecutable))
            {
                LogWarn("Cloudflare binary (cloudflared) not found. Running in local mode only.");
                return;
            }

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = cfExecutable,
                    Arguments = $"tunnel --url http://127.0.0.1:{Port}",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                _cloudflaredProcess = new Process { StartInfo = psi };
                _cloudflaredProcess.ErrorDataReceived += (s, e) =>
                {
                    if (string.IsNullOrEmpty(e.Data)) return;
                    var match = Regex.Match(e.Data, @"https://[a-zA-Z0-9-]+\.trycloudflare\.com");
                    if (match.Success)
                    {
                        var httpUrl = match.Value;
                        var wssUrl = httpUrl.Replace("https://", "wss://");
                        LogSuccess($"[CLOUDFLARE TUNNEL ONLINE] Relay available globally at: {wssUrl}");

                        try
                        {
                            var tunnelJson = JsonSerializer.Serialize(new { url = wssUrl, lanUrl = $"ws://127.0.0.1:{Port}" });
                            File.WriteAllText(TunnelFile, tunnelJson);
                        }
                        catch { }
                    }
                };

                _cloudflaredProcess.Start();
                _cloudflaredProcess.BeginErrorReadLine();
                LogInfo("Started Cloudflare trycloudflare quick tunnel.");
            }
            catch (Exception ex)
            {
                LogWarn($"Could not launch Cloudflare tunnel: {ex.Message}");
            }
        }

        private static void StopCloudflareTunnel()
        {
            if (_cloudflaredProcess != null && !_cloudflaredProcess.HasExited)
            {
                try
                {
                    _cloudflaredProcess.Kill(true);
                    _cloudflaredProcess.Dispose();
                }
                catch { }
            }
        }

        private static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
 ███╗   ███╗███████╗███████╗███████╗ █████╗ 
 ████╗ ████║██╔════╝██╔════╝██╔════╝██╔══██╗
 ██╔████╔██║█████╗  ███████╗███████╗███████║
 ██║╚██╔╝██║██╔══╝  ╚════██║╚════██║██╔══██║
 ██║ ╚═╝ ██║███████╗███████║███████║██║  ██║
 ╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
 Sovereign P2P/E2EE Native C# Relay Server
");
            Console.ResetColor();
        }

        private static void LogInfo(string msg) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [INFO] {msg}");
        private static void LogSuccess(string msg) { Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [OK] {msg}"); Console.ResetColor(); }
        private static void LogWarn(string msg) { Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [WARN] {msg}"); Console.ResetColor(); }
        private static void LogError(string msg) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [ERROR] {msg}"); Console.ResetColor(); }
    }
}
