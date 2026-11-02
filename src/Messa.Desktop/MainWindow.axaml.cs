using System;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.IO;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Messa.Core.Crypto;
using Messa.Core.Models;

namespace Messa.Desktop
{
    public class ChatMessage
    {
        public string Header { get; set; } = string.Empty;
        public string Text { get; set; } = string.Empty;
        public string Time { get; set; } = string.Empty;
        public string StatusBadge { get; set; } = string.Empty;
        public IBrush BackgroundColor { get; set; } = new SolidColorBrush(Color.Parse("#1F2937"));
        public HorizontalAlignment Alignment { get; set; } = HorizontalAlignment.Left;
    }

    public partial class MainWindow : Window
    {
        private IdentityKey _myKey;
        private ClientWebSocket? _webSocket;
        private CancellationTokenSource? _cts;
        private readonly ObservableCollection<ChatMessage> _messages = new();
        private readonly string _keyFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Messa", "identity.json");

        // Double Ratchet Sessions by Peer Fingerprint
        private readonly ConcurrentDictionary<string, DoubleRatchetSession> _sessions = new();
        private string? _activePeerFingerprint;
        private string? _activePeerUsername;

        // Pending lookup completions
        private TaskCompletionSource<PreKeyBundle?>? _pendingLookup;

        public MainWindow()
        {
            InitializeComponent();
            MessagesList.ItemsSource = _messages;

            _myKey = LoadOrCreateIdentity();
            MyFingerprintBox.Text = _myKey.Fingerprint;
            UsernameBox.Text = _myKey.Username;

            AddSystemMessage("Double Ratchet & ECDSA Signature engine ready.");
        }

        private IdentityKey LoadOrCreateIdentity()
        {
            try
            {
                var dir = Path.GetDirectoryName(_keyFile);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

                if (File.Exists(_keyFile))
                {
                    var key = JsonSerializer.Deserialize<IdentityKey>(File.ReadAllText(_keyFile));
                    if (key != null && !string.IsNullOrEmpty(key.SignedPreKeyPrivateKeyBase64)) return key;
                }
            }
            catch { }

            var newKey = IdentityKey.Generate();
            SaveIdentity(newKey);
            return newKey;
        }

        private void SaveIdentity(IdentityKey key)
        {
            try
            {
                var dir = Path.GetDirectoryName(_keyFile);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(_keyFile, JsonSerializer.Serialize(key, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        private async void OnConnectClicked(object? sender, RoutedEventArgs e)
        {
            if (_webSocket != null && _webSocket.State == WebSocketState.Open)
            {
                await DisconnectAsync();
                return;
            }

            var serverUrl = ServerUrlBox.Text?.Trim();
            if (string.IsNullOrEmpty(serverUrl)) return;

            try
            {
                ConnectBtn.IsEnabled = false;
                StatusText.Text = "Connecting...";
                StatusDot.Fill = new SolidColorBrush(Color.Parse("#FFA500"));

                _cts = new CancellationTokenSource();
                _webSocket = new ClientWebSocket();

                await _webSocket.ConnectAsync(new Uri(serverUrl), _cts.Token);

                // Register client with server
                var regPacket = new ProtocolPacket
                {
                    Type = "register",
                    Fingerprint = _myKey.Fingerprint,
                    Username = _myKey.Username
                };
                await SendJsonAsync(regPacket);

                StatusDot.Fill = new SolidColorBrush(Color.Parse("#2ECC71"));
                StatusText.Text = "Connected";
                ConnectBtn.Content = "Disconnect";
                ConnectBtn.IsEnabled = true;
                AddSystemMessage($"Connected to {serverUrl}.");

                // Auto-publish profile if username is specified
                if (!string.IsNullOrEmpty(_myKey.Username))
                {
                    await PublishProfileInternalAsync();
                }

                _ = ReceiveLoopAsync(_webSocket, _cts.Token);
            }
            catch (Exception ex)
            {
                StatusDot.Fill = new SolidColorBrush(Color.Parse("#FF4D4D"));
                StatusText.Text = "Connection Failed";
                ConnectBtn.IsEnabled = true;
                AddSystemMessage($"Connection error: {ex.Message}");
            }
        }

        private async Task DisconnectAsync()
        {
            try
            {
                _cts?.Cancel();
                if (_webSocket != null && _webSocket.State == WebSocketState.Open)
                {
                    await _webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closed", CancellationToken.None);
                }
            }
            catch { }
            finally
            {
                _webSocket?.Dispose();
                _webSocket = null;
                StatusDot.Fill = new SolidColorBrush(Color.Parse("#FF4D4D"));
                StatusText.Text = "Disconnected";
                ConnectBtn.Content = "Connect";
                ConnectBtn.IsEnabled = true;
                AddSystemMessage("Disconnected from relay.");
            }
        }

        private async void OnPublishProfileClicked(object? sender, RoutedEventArgs e)
        {
            var username = UsernameBox.Text?.Trim().TrimStart('@') ?? "";
            _myKey.Username = username;
            SaveIdentity(_myKey);

            if (_webSocket == null || _webSocket.State != WebSocketState.Open)
            {
                AddSystemMessage("Cannot publish: please connect to server first.");
                return;
            }

            await PublishProfileInternalAsync();
        }

        private async Task PublishProfileInternalAsync()
        {
            var bundle = PreKeyBundle.Create(_myKey);
            var packet = new ProtocolPacket
            {
                Type = "publish_bundle",
                Bundle = bundle
            };
            await SendJsonAsync(packet);
            AddSystemMessage($"Published PreKey Bundle for @{_myKey.Username} to Server Directory.");
        }

        private async void OnInitRatchetClicked(object? sender, RoutedEventArgs e)
        {
            var query = PeerSearchBox.Text?.Trim();
            if (string.IsNullOrEmpty(query)) return;

            if (_webSocket == null || _webSocket.State != WebSocketState.Open)
            {
                AddSystemMessage("Please connect to server first.");
                return;
            }

            AddSystemMessage($"Looking up PreKey Bundle for '{query}' in Server Directory...");
            _pendingLookup = new TaskCompletionSource<PreKeyBundle?>();

            await SendJsonAsync(new ProtocolPacket
            {
                Type = "lookup_bundle",
                Query = query
            });

            var completedTask = await Task.WhenAny(_pendingLookup.Task, Task.Delay(5000));
            if (completedTask == _pendingLookup.Task)
            {
                var bundle = await _pendingLookup.Task;
                if (bundle != null)
                {
                    // Verify bundle signature
                    if (!bundle.Verify())
                    {
                        AddSystemMessage("❌ SECURITY WARNING: PreKey bundle signature verification failed!");
                        return;
                    }

                    try
                    {
                        var session = DoubleRatchetSession.Initiate(_myKey, bundle);
                        _sessions[bundle.Fingerprint] = session;
                        _activePeerFingerprint = bundle.Fingerprint;
                        _activePeerUsername = string.IsNullOrEmpty(bundle.Username) ? bundle.Fingerprint[..8] : $"@{bundle.Username}";

                        ActivePeerLabel.Text = $"Chatting with: {_activePeerUsername} (Double Ratchet Active 🔒)";
                        ActivePeerLabel.Foreground = new SolidColorBrush(Color.Parse("#34D399"));

                        AddSystemMessage($"✅ Double Ratchet Session initialized with {_activePeerUsername}! Forward Secrecy & Break-in Recovery active.");
                    }
                    catch (Exception ex)
                    {
                        AddSystemMessage($"Failed to initiate ratchet: {ex.Message}");
                    }
                }
            }
            else
            {
                AddSystemMessage("Lookup timed out. User might not exist or be registered.");
            }
        }

        private async Task ReceiveLoopAsync(ClientWebSocket socket, CancellationToken ct)
        {
            var buffer = new byte[1024 * 64];

            try
            {
                while (socket.State == WebSocketState.Open && !ct.IsCancellationRequested)
                {
                    using var ms = new MemoryStream();
                    WebSocketReceiveResult result;
                    do
                    {
                        result = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), ct);
                        if (result.MessageType == WebSocketMessageType.Close)
                        {
                            await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", ct);
                            Dispatcher.UIThread.Post(() => _ = DisconnectAsync());
                            return;
                        }
                        ms.Write(buffer, 0, result.Count);
                    } while (!result.EndOfMessage);

                    var json = Encoding.UTF8.GetString(ms.ToArray());
                    var packet = JsonSerializer.Deserialize<ProtocolPacket>(json);
                    if (packet != null)
                    {
                        await ProcessIncomingPacketAsync(packet);
                    }
                }
            }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested)
                {
                    Dispatcher.UIThread.Post(() =>
                    {
                        AddSystemMessage($"Disconnected: {ex.Message}");
                        _ = DisconnectAsync();
                    });
                }
            }
        }

        private async Task ProcessIncomingPacketAsync(ProtocolPacket packet)
        {
            switch (packet.Type)
            {
                case "bundle_result":
                    _pendingLookup?.TrySetResult(packet.Bundle);
                    break;

                case "error":
                    _pendingLookup?.TrySetResult(null);
                    Dispatcher.UIThread.Post(() => AddSystemMessage($"Server error: {packet.Error}"));
                    break;

                case "status":
                    Dispatcher.UIThread.Post(() => AddSystemMessage($"Server: {packet.Status}"));
                    break;

                case "ratchet_message":
                    if (packet.RatchetMessage != null)
                    {
                        await HandleIncomingRatchetMessageAsync(packet);
                    }
                    break;
            }
        }

        private async Task HandleIncomingRatchetMessageAsync(ProtocolPacket packet)
        {
            var msg = packet.RatchetMessage!;
            var senderFp = msg.SenderFingerprint;

            // Check if we have an active session with this peer
            if (!_sessions.TryGetValue(senderFp, out var session))
            {
                // We need sender's Identity Signing & DH keys
                if (string.IsNullOrEmpty(packet.SenderIdentityDhKeyBase64))
                {
                    Dispatcher.UIThread.Post(() => AddSystemMessage("Received message without sender DH key material."));
                    return;
                }

                // Lookup sender's bundle from Key Directory
                _pendingLookup = new TaskCompletionSource<PreKeyBundle?>();
                await SendJsonAsync(new ProtocolPacket { Type = "lookup_bundle", Query = senderFp });

                var senderBundle = await _pendingLookup.Task;
                if (senderBundle == null || !senderBundle.Verify())
                {
                    Dispatcher.UIThread.Post(() => AddSystemMessage("❌ Cannot verify sender's PreKey Bundle!"));
                    return;
                }

                session = DoubleRatchetSession.Accept(
                    _myKey,
                    senderFp,
                    senderBundle.IdentitySigningKeyBase64,
                    packet.SenderIdentityDhKeyBase64,
                    Convert.FromBase64String(msg.DhPublicKeyBase64));

                _sessions[senderFp] = session;
                _activePeerFingerprint = senderFp;
                _activePeerUsername = string.IsNullOrEmpty(senderBundle.Username) ? senderFp[..8] : $"@{senderBundle.Username}";

                Dispatcher.UIThread.Post(() =>
                {
                    ActivePeerLabel.Text = $"Chatting with: {_activePeerUsername} (Double Ratchet Active 🔒)";
                    ActivePeerLabel.Foreground = new SolidColorBrush(Color.Parse("#34D399"));
                });
            }

            try
            {
                var decrypted = session.Decrypt(msg);
                var peerDisplay = _activePeerUsername ?? senderFp[..8];

                Dispatcher.UIThread.Post(() =>
                {
                    _messages.Add(new ChatMessage
                    {
                        Header = $"From: {peerDisplay}",
                        Text = decrypted,
                        Time = DateTime.Now.ToString("HH:mm"),
                        StatusBadge = $"Verified ECDSA • Ratchet #{msg.MessageNumber}",
                        BackgroundColor = new SolidColorBrush(Color.Parse("#232D3F")),
                        Alignment = HorizontalAlignment.Left
                    });
                });
            }
            catch (Exception ex)
            {
                Dispatcher.UIThread.Post(() => AddSystemMessage($"❌ Decrypt / Signature Error: {ex.Message}"));
            }
        }

        private async void OnSendClicked(object? sender, RoutedEventArgs e) => await SendCurrentMessageAsync();

        private async void OnMessageInputKeyDown(object? sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) await SendCurrentMessageAsync();
        }

        private async Task SendCurrentMessageAsync()
        {
            var text = MessageInputBox.Text?.Trim();
            if (string.IsNullOrEmpty(text)) return;

            if (_webSocket == null || _webSocket.State != WebSocketState.Open)
            {
                AddSystemMessage("Cannot send: not connected to relay.");
                return;
            }

            if (string.IsNullOrEmpty(_activePeerFingerprint) || !_sessions.TryGetValue(_activePeerFingerprint, out var session))
            {
                AddSystemMessage("Please find a contact with 'Find & Init Ratchet' before sending.");
                return;
            }

            try
            {
                // Encrypt via Double Ratchet + sign with ECDSA P-256
                var msg = session.Encrypt(text, _myKey);

                var packet = new ProtocolPacket
                {
                    Type = "ratchet_message",
                    RatchetMessage = msg,
                    SenderIdentityDhKeyBase64 = _myKey.DhPublicKeyBase64
                };

                await SendJsonAsync(packet);

                _messages.Add(new ChatMessage
                {
                    Header = "Me",
                    Text = text,
                    Time = DateTime.Now.ToString("HH:mm"),
                    StatusBadge = $"Signed ECDSA • Ratchet #{msg.MessageNumber}",
                    BackgroundColor = new SolidColorBrush(Color.Parse("#2B5278")),
                    Alignment = HorizontalAlignment.Right
                });

                MessageInputBox.Text = string.Empty;
            }
            catch (Exception ex)
            {
                AddSystemMessage($"Encryption Error: {ex.Message}");
            }
        }

        private async Task SendJsonAsync(ProtocolPacket packet)
        {
            if (_webSocket == null || _webSocket.State != WebSocketState.Open) return;
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(packet));
            await _webSocket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, CancellationToken.None);
        }

        private void AddSystemMessage(string text)
        {
            _messages.Add(new ChatMessage
            {
                Header = "System",
                Text = text,
                Time = DateTime.Now.ToString("HH:mm"),
                BackgroundColor = new SolidColorBrush(Color.Parse("#1A202C")),
                Alignment = HorizontalAlignment.Center
            });
        }
    }
}
