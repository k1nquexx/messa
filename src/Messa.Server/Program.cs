using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
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
        private static readonly string ProfilesFile = Path.Combine(DataDir, "profiles.json");
        private static readonly string TunnelFile = Path.Combine(DataDir, "tunnel.json");

        // Key Directory & Pre-Key Bundles
        private static readonly ConcurrentDictionary<string, PreKeyBundle> BundlesByFingerprint = new();
        private static readonly ConcurrentDictionary<string, string> FingerprintByUsername = new(StringComparer.OrdinalIgnoreCase);

        // Profiles
        private static readonly ConcurrentDictionary<string, UserProfile> ProfilesByFingerprint = new();

        // Offline Dead-Drop queue
        private static readonly ConcurrentDictionary<string, List<ProtocolPacket>> OfflineQueue = new();
        private static Process? _cloudflaredProcess;

        static async Task Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.Title = "MESSA - Sovereign Relay Server (C# / .NET 8)";

            PrintBanner();

            Directory.CreateDirectory(DataDir);
            LoadProfiles();
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

            LogInfo("Relay is active with Challenge-Response Handshake and SRP-6a 2FA protection.");

            while (true)
            {
                try
                {
                    var context = await httpListener.GetContextAsync();
                    if (context.Request.IsWebSocketRequest)
                    {
                        _ = ProcessWebSocketSessionAsync(context);
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

        private static async Task ProcessWebSocketSessionAsync(HttpListenerContext context)
        {
            HttpListenerWebSocketContext wsCtx;
            try
            {
                wsCtx = await context.AcceptWebSocketAsync(subProtocol: null);
            }
            catch (Exception ex)
            {
                context.Response.StatusCode = 500;
                context.Response.Close();
                LogError($"WebSocket handshake error: {ex.Message}");
                return;
            }

            var webSocket = wsCtx.WebSocket;
            string? authenticatedFingerprint = null;

            try
            {
                // STEP 1: Mandatory Challenge-Response Handshake
                // Generate cryptographically random 32-byte nonce
                var nonceBytes = new byte[32];
                RandomNumberGenerator.Fill(nonceBytes);
                var nonceBase64 = Convert.ToBase64String(nonceBytes);

                // Send challenge to client
                var challengePacket = new ProtocolPacket
                {
                    Type = "auth_challenge",
                    Nonce = nonceBase64
                };
                await SendJsonAsync(webSocket, challengePacket);

                // Await client auth_response with 10-second timeout
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var authPacket = await ReceivePacketAsync(webSocket, cts.Token);

                if (authPacket == null || authPacket.Type != "auth_response" ||
                    string.IsNullOrEmpty(authPacket.Fingerprint) ||
                    string.IsNullOrEmpty(authPacket.SigningPublicKey) ||
                    string.IsNullOrEmpty(authPacket.Signature))
                {
                    LogWarn("Handshake rejected: missing or malformed auth_response.");
                    await webSocket.CloseAsync(WebSocketCloseStatus.PolicyViolation, "Handshake failed", CancellationToken.None);
                    return;
                }

                // Verify 1: SHA-256(SigningPublicKey) == Fingerprint
                var pubBytes = Convert.FromBase64String(authPacket.SigningPublicKey);
                using var sha = SHA256.Create();
                var expectedFp = Convert.ToHexString(sha.ComputeHash(pubBytes)).ToLowerInvariant();

                if (!string.Equals(expectedFp, authPacket.Fingerprint, StringComparison.OrdinalIgnoreCase))
                {
                    LogWarn($"Handshake rejected: Fingerprint does not match public key! Claimed: {authPacket.Fingerprint}");
                    await webSocket.CloseAsync(WebSocketCloseStatus.PolicyViolation, "Fingerprint mismatch", CancellationToken.None);
                    return;
                }

                // Verify 2: ECDSA Signature of Challenge Nonce
                var sigBytes = Convert.FromBase64String(authPacket.Signature);
                var isSigValid = IdentityKey.VerifySignature(nonceBytes, sigBytes, authPacket.SigningPublicKey);

                if (!isSigValid)
                {
                    LogWarn($"Handshake rejected: Invalid digital signature for {authPacket.Fingerprint[..8]}... Spoofing attempt blocked!");
                    await webSocket.CloseAsync(WebSocketCloseStatus.PolicyViolation, "Invalid signature", CancellationToken.None);
                    return;
                }

                // Verify 3: SRP-6a 2FA Cloud Password (if enabled on account)
                if (ProfilesByFingerprint.TryGetValue(authPacket.Fingerprint, out var userProfile) && userProfile.Has2FA)
                {
                    if (string.IsNullOrEmpty(authPacket.TwoFactorProof) || string.IsNullOrEmpty(authPacket.TwoFactorA))
                    {
                        // Challenge client for 2FA SRP-6a
                        var (serverB, secretB) = Srp6aAuth.GenerateServerChallenge(userProfile.TwoFactorVerifierBase64!);
                        await SendJsonAsync(webSocket, new ProtocolPacket
                        {
                            Type = "auth_2fa_challenge",
                            TwoFactorSalt = userProfile.TwoFactorSaltBase64,
                            TwoFactorB = serverB
                        });

                        var twoFaResponse = await ReceivePacketAsync(webSocket, cts.Token);
                        if (twoFaResponse == null ||
                            !Srp6aAuth.VerifyClientProof(
                                twoFaResponse.TwoFactorA ?? "",
                                serverB,
                                secretB,
                                userProfile.TwoFactorVerifierBase64!,
                                twoFaResponse.TwoFactorProof ?? ""))
                        {
                            LogWarn($"Handshake rejected: 2FA cloud password verification failed for {authPacket.Fingerprint[..8]}!");
                            await webSocket.CloseAsync(WebSocketCloseStatus.PolicyViolation, "2FA verification failed", CancellationToken.None);
                            return;
                        }
                    }
                }

                // Authentication succeeded! Bind socket
                authenticatedFingerprint = authPacket.Fingerprint;
                ConnectedClients[authenticatedFingerprint] = webSocket;
                LogSuccess($"[AUTH OK] Cryptographically authenticated client: {authenticatedFingerprint[..8]}...");

                // Ensure profile exists
                if (!ProfilesByFingerprint.TryGetValue(authenticatedFingerprint, out userProfile))
                {
                    userProfile = new UserProfile
                    {
                        Fingerprint = authenticatedFingerprint,
                        Username = authPacket.Username ?? "",
                        DisplayName = authPacket.Username ?? authenticatedFingerprint[..8]
                    };
                    ProfilesByFingerprint[authenticatedFingerprint] = userProfile;
                    if (!string.IsNullOrEmpty(userProfile.Username))
                    {
                        FingerprintByUsername[userProfile.Username] = authenticatedFingerprint;
                    }
                    SaveProfiles();
                }

                // Send auth_success
                await SendJsonAsync(webSocket, new ProtocolPacket
                {
                    Type = "auth_success",
                    Profile = userProfile
                });

                // Flush dead-drop messages
                await DeliverOfflineMessagesAsync(authenticatedFingerprint, webSocket);

                // STEP 2: Main Message Loop
                while (webSocket.State == WebSocketState.Open)
                {
                    var packet = await ReceivePacketAsync(webSocket, CancellationToken.None);
                    if (packet == null) break;

                    switch (packet.Type)
                    {
                        case "publish_bundle":
                            if (packet.Bundle != null && packet.Bundle.Verify())
                            {
                                BundlesByFingerprint[authenticatedFingerprint] = packet.Bundle;
                                if (!string.IsNullOrEmpty(packet.Bundle.Username))
                                {
                                    FingerprintByUsername[packet.Bundle.Username] = authenticatedFingerprint;
                                }
                                SaveKeyDirectory();
                                LogSuccess($"[KEY-DIR] Published verified PreKey bundle for @{packet.Bundle.Username}");
                                await SendJsonAsync(webSocket, new ProtocolPacket { Type = "status", Status = "bundle_published" });
                            }
                            break;

                        case "lookup_bundle":
                            if (!string.IsNullOrEmpty(packet.Query))
                            {
                                var q = packet.Query.Trim().TrimStart('@');
                                PreKeyBundle? b = null;
                                if (BundlesByFingerprint.TryGetValue(q, out var b1)) b = b1;
                                else if (FingerprintByUsername.TryGetValue(q, out var fp) && BundlesByFingerprint.TryGetValue(fp, out var b2)) b = b2;

                                if (b != null)
                                {
                                    await SendJsonAsync(webSocket, new ProtocolPacket { Type = "bundle_result", Bundle = b });
                                }
                                else
                                {
                                    await SendJsonAsync(webSocket, new ProtocolPacket { Type = "error", Error = "User not found" });
                                }
                            }
                            break;

                        case "update_profile":
                            if (packet.Profile != null)
                            {
                                var p = packet.Profile;
                                p.Fingerprint = authenticatedFingerprint;
                                p.UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                                if (packet.Enable2FA == true && !string.IsNullOrEmpty(packet.TwoFactorSalt) && !string.IsNullOrEmpty(packet.TwoFactorProof))
                                {
                                    p.Has2FA = true;
                                    p.TwoFactorSaltBase64 = packet.TwoFactorSalt;
                                    p.TwoFactorVerifierBase64 = packet.TwoFactorProof;
                                    LogSuccess($"[2FA] Enabled Cloud Password for {p.Username}");
                                }
                                else if (packet.Enable2FA == false)
                                {
                                    p.Has2FA = false;
                                    p.TwoFactorSaltBase64 = null;
                                    p.TwoFactorVerifierBase64 = null;
                                    LogInfo($"[2FA] Disabled Cloud Password for {p.Username}");
                                }

                                ProfilesByFingerprint[authenticatedFingerprint] = p;
                                if (!string.IsNullOrEmpty(p.Username))
                                {
                                    FingerprintByUsername[p.Username] = authenticatedFingerprint;
                                }
                                SaveProfiles();
                                await SendJsonAsync(webSocket, new ProtocolPacket { Type = "profile_updated", Profile = p });
                            }
                            break;

                        case "search_users":
                            if (!string.IsNullOrEmpty(packet.Query))
                            {
                                var q = packet.Query.Trim().TrimStart('@');
                                var matches = ProfilesByFingerprint.Values
                                    .Where(pr => pr.Username.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                                                 pr.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                                                 pr.Fingerprint.Equals(q, StringComparison.OrdinalIgnoreCase))
                                    .Take(20)
                                    .ToList();

                                await SendJsonAsync(webSocket, new ProtocolPacket
                                {
                                    Type = "search_results",
                                    SearchResults = matches
                                });
                            }
                            break;

                        case "ratchet_message":
                            if (packet.RatchetMessage != null)
                            {
                                var recipient = packet.RatchetMessage.RecipientFingerprint;
                                if (ConnectedClients.TryGetValue(recipient, out var recipientSocket) && recipientSocket.State == WebSocketState.Open)
                                {
                                    await SendJsonAsync(recipientSocket, packet);
                                    await SendJsonAsync(webSocket, new ProtocolPacket { Type = "status", Status = "delivered" });
                                }
                                else
                                {
                                    EnqueueOfflineMessage(recipient, packet);
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
                LogWarn($"Session ended for client ({ex.Message})");
            }
            finally
            {
                if (!string.IsNullOrEmpty(authenticatedFingerprint))
                {
                    ConnectedClients.TryRemove(authenticatedFingerprint, out _);
                    LogInfo($"Client disconnected: {authenticatedFingerprint[..8]}...");
                }
                webSocket.Dispose();
            }
        }

        private static async Task<ProtocolPacket?> ReceivePacketAsync(WebSocket socket, CancellationToken ct)
        {
            var buffer = new byte[1024 * 64];
            using var ms = new MemoryStream();
            WebSocketReceiveResult res;
            do
            {
                res = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), ct);
                if (res.MessageType == WebSocketMessageType.Close)
                {
                    await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", ct);
                    return null;
                }
                ms.Write(buffer, 0, res.Count);
            } while (!res.EndOfMessage);

            var json = Encoding.UTF8.GetString(ms.ToArray());
            return JsonSerializer.Deserialize<ProtocolPacket>(json);
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

        private static void LoadProfiles()
        {
            if (File.Exists(ProfilesFile))
            {
                try
                {
                    var data = JsonSerializer.Deserialize<Dictionary<string, UserProfile>>(File.ReadAllText(ProfilesFile));
                    if (data != null)
                    {
                        foreach (var kvp in data)
                        {
                            ProfilesByFingerprint[kvp.Key] = kvp.Value;
                            if (!string.IsNullOrEmpty(kvp.Value.Username))
                            {
                                FingerprintByUsername[kvp.Value.Username] = kvp.Key;
                            }
                        }
                        LogInfo($"Loaded {ProfilesByFingerprint.Count} user profile(s).");
                    }
                }
                catch { }
            }
        }

        private static void SaveProfiles()
        {
            try
            {
                var dict = new Dictionary<string, UserProfile>(ProfilesByFingerprint);
                File.WriteAllText(ProfilesFile, JsonSerializer.Serialize(dict, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
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

        private static void PrintBanner() => Console.WriteLine("\n[MESSA] Sovereign Native C# Relay Server (Challenge-Response + SRP-6a 2FA)\n");
        private static void LogInfo(string m) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [INFO] {m}");
        private static void LogSuccess(string m) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [OK] {m}");
        private static void LogWarn(string m) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [WARN] {m}");
        private static void LogError(string m) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [ERROR] {m}");
    }
}
