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
using Messa.Server.Database;
using Messa.Server.Messaging;

namespace Messa.Server
{
    class Program
    {
        private static readonly int Port = 8080;

        // Multi-Device Socket Tracking: AccountFingerprint -> (DeviceId -> WebSocket)
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, WebSocket>> ConnectedDevicesByAccount = new();
        private static readonly ConcurrentDictionary<string, IDisposable> SubscriptionsByAccount = new();

        private static readonly string DataDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data");
        private static readonly string TunnelFile = Path.Combine(DataDir, "tunnel.json");

        // Server Database: PostgreSQL (Npgsql) or SQLite
        private static IServerDatabase _database = null!;

        // Event-driven Pub/Sub Broker: ChannelMessageBus or RedisMessageBus
        private static IMessageBus _messageBus = null!;

        private static Process? _cloudflaredProcess;

        static async Task Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.Title = "MESSA - Sovereign Multi-Device Cloud Relay (.NET 8)";

            PrintBanner();

            Directory.CreateDirectory(DataDir);

            // 1. Initialize Server Database (PostgreSQL or SQLite)
            var pgConn = Environment.GetEnvironmentVariable("MESSA_POSTGRES_CONNECTION") ??
                         Environment.GetEnvironmentVariable("MESSA_PG_CONNECTION");

            if (!string.IsNullOrEmpty(pgConn))
            {
                LogInfo("Configuring PostgreSQL database backend (Npgsql)...");
                _database = new PostgresServerDatabase(pgConn);
            }
            else
            {
                var sqlitePath = Path.Combine(DataDir, "messa_server.db");
                LogInfo($"Configuring ACID SQLite database backend ({sqlitePath})...");
                _database = new SqliteServerDatabase(sqlitePath);
            }

            await _database.InitializeAsync();
            LogSuccess("Server database initialized with WAL mode & multi-device schema.");

            // 2. Initialize Event-driven Pub/Sub Message Bus (Redis or In-Memory Channel)
            var redisConn = Environment.GetEnvironmentVariable("MESSA_REDIS_CONNECTION") ??
                            Environment.GetEnvironmentVariable("MESSA_REDIS_URL");

            if (!string.IsNullOrEmpty(redisConn))
            {
                LogInfo($"Configuring Redis Pub/Sub cluster broker ({redisConn})...");
                _messageBus = new RedisMessageBus(redisConn);
            }
            else
            {
                LogInfo("Configuring high-performance async Channel Message Bus (single-node broker)...");
                _messageBus = new ChannelMessageBus();
            }

            await _messageBus.StartAsync();
            LogSuccess("Pub/Sub Event Broker active.");

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

            AppDomain.CurrentDomain.ProcessExit += (s, e) =>
            {
                StopCloudflareTunnel();
                _messageBus.DisposeAsync().AsTask().GetAwaiter().GetResult();
            };

            LogInfo("Relay is active: Delivery status tracking (Sent/Delivered/Read) and Pub/Sub cluster scaling enabled.");

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
                        var resp = Encoding.UTF8.GetBytes("{\"status\":\"ok\",\"service\":\"MESSA Sovereign Cloud Relay\",\"cluster\":true}");
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
            string? deviceId = null;

            try
            {
                // STEP 1: Mandatory Challenge-Response Handshake
                var nonceBytes = new byte[32];
                RandomNumberGenerator.Fill(nonceBytes);
                var nonceBase64 = Convert.ToBase64String(nonceBytes);

                await SendJsonAsync(webSocket, new ProtocolPacket
                {
                    Type = "auth_challenge",
                    Nonce = nonceBase64
                });

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
                    LogWarn($"Handshake rejected: Fingerprint mismatch! Claimed: {authPacket.Fingerprint}");
                    await webSocket.CloseAsync(WebSocketCloseStatus.PolicyViolation, "Fingerprint mismatch", CancellationToken.None);
                    return;
                }

                // Verify 2: ECDSA Signature of Challenge Nonce
                var sigBytes = Convert.FromBase64String(authPacket.Signature);
                var isSigValid = IdentityKey.VerifySignature(nonceBytes, sigBytes, authPacket.SigningPublicKey);

                if (!isSigValid)
                {
                    LogWarn($"Handshake rejected: Invalid digital signature for {authPacket.Fingerprint[..8]}!");
                    await webSocket.CloseAsync(WebSocketCloseStatus.PolicyViolation, "Invalid signature", CancellationToken.None);
                    return;
                }

                // Verify 3: SRP-6a 2FA Cloud Password (if enabled)
                var userProfile = await _database.GetUserAsync(authPacket.Fingerprint);
                if (userProfile != null && userProfile.Has2FA)
                {
                    if (string.IsNullOrEmpty(authPacket.TwoFactorProof) || string.IsNullOrEmpty(authPacket.TwoFactorA))
                    {
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

                // STEP 2: Authenticated! Register this Device for this Account
                authenticatedFingerprint = authPacket.Fingerprint;
                deviceId = string.IsNullOrEmpty(authPacket.DeviceId) ? $"dev-{Guid.NewGuid():N}"[..12] : authPacket.DeviceId;

                var devices = ConnectedDevicesByAccount.GetOrAdd(authenticatedFingerprint, _ => new ConcurrentDictionary<string, WebSocket>());
                devices[deviceId] = webSocket;

                // Subscribe this node to Pub/Sub events for this account if not already subscribed
                EnsureAccountSubscribed(authenticatedFingerprint);

                var totalDevices = devices.Count;
                LogSuccess($"[AUTH OK] Account: {authenticatedFingerprint[..8]}... Device: {deviceId} connected (Total online devices: {totalDevices})");

                if (userProfile == null)
                {
                    userProfile = new UserProfile
                    {
                        Fingerprint = authenticatedFingerprint,
                        Username = authPacket.Username ?? "",
                        DisplayName = authPacket.Username ?? authenticatedFingerprint[..8],
                        UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    };
                    await _database.SaveUserAsync(userProfile);
                }

                var currentPts = await _database.GetCurrentPtsAsync(authenticatedFingerprint);

                // Send auth_success with current PTS
                await SendJsonAsync(webSocket, new ProtocolPacket
                {
                    Type = "auth_success",
                    DeviceId = deviceId,
                    Profile = userProfile,
                    CurrentPts = currentPts
                });

                // STEP 3: Message Loop
                while (webSocket.State == WebSocketState.Open)
                {
                    var packet = await ReceivePacketAsync(webSocket, CancellationToken.None);
                    if (packet == null) break;

                    switch (packet.Type)
                    {
                        case "get_difference":
                            var fromPts = packet.FromPts ?? 0;
                            var (diffMessages, latestPts) = await _database.GetDifferenceAsync(authenticatedFingerprint, fromPts);
                            await SendJsonAsync(webSocket, new ProtocolPacket
                            {
                                Type = "difference_result",
                                Difference = diffMessages,
                                CurrentPts = latestPts
                            });
                            LogInfo($"[PTS SYNC] Sent {diffMessages.Count} updates (pts > {fromPts}) to device {deviceId}");
                            break;

                        case "send_message":
                            if (!string.IsNullOrEmpty(packet.Query) || packet.CloudMessage != null)
                            {
                                var recipientFp = packet.Query ?? packet.CloudMessage?.PeerFingerprint ?? "";
                                var ciphertext = packet.CloudMessage?.CiphertextBase64 ?? "";
                                var tag = packet.CloudMessage?.TagBase64 ?? "";
                                var iv = packet.CloudMessage?.IvBase64 ?? "";
                                var sig = packet.CloudMessage?.SignatureBase64 ?? "";
                                var plainText = packet.CloudMessage?.Text ?? "";
                                var clientMsgId = packet.CloudMessage?.Id;

                                if (!string.IsNullOrEmpty(recipientFp))
                                {
                                    // 1. ACID Store & Sequence: Status is initially 'Sent' (1 checkmark)
                                    var (recipientRecord, senderRecord) = await _database.StoreAndSequenceMessageAsync(
                                        authenticatedFingerprint,
                                        recipientFp,
                                        ciphertext,
                                        tag,
                                        iv,
                                        sig,
                                        plainText,
                                        clientMsgId);

                                    // 2. Deliver to Recipient's devices via Pub/Sub broker
                                    await _messageBus.PublishAsync($"user:{recipientFp}", new ProtocolPacket
                                    {
                                        Type = "new_message",
                                        CloudMessage = recipientRecord,
                                        Pts = recipientRecord.Pts
                                    });

                                    // 3. Multi-device sync: Fan-out echo to ALL OTHER devices of Sender (e.g. PC if sent from Phone)
                                    await _messageBus.PublishAsync($"user:{authenticatedFingerprint}", new ProtocolPacket
                                    {
                                        Type = "new_message",
                                        CloudMessage = senderRecord,
                                        Pts = senderRecord.Pts,
                                        DeviceId = deviceId
                                    });

                                    // 4. Acknowledge sending socket with Sent status (1 checkmark)
                                    await SendJsonAsync(webSocket, new ProtocolPacket
                                    {
                                        Type = "status",
                                        Status = "sent",
                                        MessageId = recipientRecord.Id,
                                        Pts = senderRecord.Pts,
                                        DeliveryStatus = MessageDeliveryStatus.Sent
                                    });

                                    // 5. If recipient is currently online, mark as Delivered immediately
                                    bool isRecipientOnline = ConnectedDevicesByAccount.ContainsKey(recipientFp);
                                    if (isRecipientOnline)
                                    {
                                        await _database.UpdateMessageStatusAsync(recipientRecord.Id, recipientFp, MessageDeliveryStatus.Delivered);

                                        // Notify sender devices: Delivered (2 gray checkmarks)
                                        await _messageBus.PublishAsync($"user:{authenticatedFingerprint}", new ProtocolPacket
                                        {
                                            Type = "message_status_update",
                                            MessageId = recipientRecord.Id,
                                            ChatId = recipientFp,
                                            DeliveryStatus = MessageDeliveryStatus.Delivered
                                        });
                                    }

                                    LogInfo($"[MSG ROUTED] From {authenticatedFingerprint[..8]} to {recipientFp[..8]} (Sender Pts: {senderRecord.Pts}, Recipient Pts: {recipientRecord.Pts}, Status: {(isRecipientOnline ? "Delivered" : "Sent")})");
                                }
                            }
                            break;

                        case "delivery_receipt":
                            if (!string.IsNullOrEmpty(packet.MessageId))
                            {
                                var peerChatId = packet.ChatId ?? "";
                                await _database.UpdateMessageStatusAsync(packet.MessageId, peerChatId, MessageDeliveryStatus.Delivered);

                                if (!string.IsNullOrEmpty(peerChatId))
                                {
                                    await _messageBus.PublishAsync($"user:{peerChatId}", new ProtocolPacket
                                    {
                                        Type = "message_status_update",
                                        MessageId = packet.MessageId,
                                        ChatId = authenticatedFingerprint,
                                        DeliveryStatus = MessageDeliveryStatus.Delivered
                                    });
                                }
                            }
                            break;

                        case "read_receipt":
                            if (!string.IsNullOrEmpty(packet.MessageId))
                            {
                                var peerChatId = packet.ChatId ?? "";
                                await _database.UpdateMessageStatusAsync(packet.MessageId, peerChatId, MessageDeliveryStatus.Read);

                                // 1. Notify the message sender that Bob has read it (2 green/blue checkmarks)
                                if (!string.IsNullOrEmpty(peerChatId))
                                {
                                    await _messageBus.PublishAsync($"user:{peerChatId}", new ProtocolPacket
                                    {
                                        Type = "message_status_update",
                                        MessageId = packet.MessageId,
                                        ChatId = authenticatedFingerprint,
                                        DeliveryStatus = MessageDeliveryStatus.Read
                                    });
                                }

                                // 2. Sync read status across Bob's other devices
                                await _messageBus.PublishAsync($"user:{authenticatedFingerprint}", new ProtocolPacket
                                {
                                    Type = "message_status_update",
                                    MessageId = packet.MessageId,
                                    ChatId = peerChatId,
                                    DeliveryStatus = MessageDeliveryStatus.Read,
                                    DeviceId = deviceId
                                });

                                LogInfo($"[READ RECEIPT] Message {packet.MessageId[..8]} marked read by {authenticatedFingerprint[..8]}");
                            }
                            break;

                        case "publish_bundle":
                            if (packet.Bundle != null && packet.Bundle.Verify())
                            {
                                await _database.SavePreKeyBundleAsync(packet.Bundle);
                                LogSuccess($"[KEY-DIR] Published verified PreKey bundle for @{packet.Bundle.Username}");
                                await SendJsonAsync(webSocket, new ProtocolPacket { Type = "status", Status = "bundle_published" });
                            }
                            break;

                        case "lookup_bundle":
                            if (!string.IsNullOrEmpty(packet.Query))
                            {
                                var bundle = await _database.GetPreKeyBundleAsync(packet.Query);
                                if (bundle != null)
                                {
                                    await SendJsonAsync(webSocket, new ProtocolPacket { Type = "bundle_result", Bundle = bundle });
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

                                await _database.SaveUserAsync(p);
                                await SendJsonAsync(webSocket, new ProtocolPacket { Type = "profile_updated", Profile = p });
                            }
                            break;

                        case "search_users":
                            if (!string.IsNullOrEmpty(packet.Query))
                            {
                                var matches = await _database.SearchUsersAsync(packet.Query, 20);
                                await SendJsonAsync(webSocket, new ProtocolPacket
                                {
                                    Type = "search_results",
                                    SearchResults = matches
                                });
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
                if (!string.IsNullOrEmpty(authenticatedFingerprint) && !string.IsNullOrEmpty(deviceId))
                {
                    if (ConnectedDevicesByAccount.TryGetValue(authenticatedFingerprint, out var devDict))
                    {
                        devDict.TryRemove(deviceId, out _);
                        if (devDict.IsEmpty)
                        {
                            ConnectedDevicesByAccount.TryRemove(authenticatedFingerprint, out _);
                            if (SubscriptionsByAccount.TryRemove(authenticatedFingerprint, out var sub))
                            {
                                sub.Dispose();
                            }
                        }
                    }
                    LogInfo($"Device {deviceId} disconnected for account {authenticatedFingerprint[..8]}...");
                }
                webSocket.Dispose();
            }
        }

        private static void EnsureAccountSubscribed(string accountFp)
        {
            SubscriptionsByAccount.GetOrAdd(accountFp, fp =>
            {
                return _messageBus.Subscribe($"user:{fp}", async packet =>
                {
                    if (ConnectedDevicesByAccount.TryGetValue(fp, out var devDict))
                    {
                        foreach (var kvp in devDict)
                        {
                            // If packet specified DeviceId to skip (e.g. echo packet from self), skip that device
                            if (!string.IsNullOrEmpty(packet.DeviceId) && packet.DeviceId == kvp.Key && packet.Type == "new_message")
                            {
                                continue;
                            }

                            if (kvp.Value.State == WebSocketState.Open)
                            {
                                try
                                {
                                    await SendJsonAsync(kvp.Value, packet);
                                }
                                catch { }
                            }
                        }
                    }
                });
            });
        }

        private static async Task<ProtocolPacket?> ReceivePacketAsync(WebSocket socket, CancellationToken ct)
        {
            var buffer = new byte[1024 * 64];
            using var ms = new MemoryStream();
            WebSocketReceiveResult res;
            do
            {
                res = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), ct);
                if (res.MessageType == WebSocketMessageType.Close) return null;
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

        private static void PrintBanner() => Console.WriteLine("\n[MESSA] Sovereign Multi-Device Cloud Relay (PostgreSQL / SQLite + Pub/Sub)\n");
        private static void LogInfo(string m) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [INFO] {m}");
        private static void LogSuccess(string m) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [OK] {m}");
        private static void LogWarn(string m) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [WARN] {m}");
        private static void LogError(string m) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [ERROR] {m}");
    }
}
