using System;
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

        public MainWindow()
        {
            InitializeComponent();
            MessagesList.ItemsSource = _messages;

            _myKey = LoadOrCreateIdentity();
            MyFingerprintBox.Text = _myKey.Fingerprint;

            AddSystemMessage("App initialized. Ready to connect via native WSS.");
        }

        private IdentityKey LoadOrCreateIdentity()
        {
            try
            {
                var dir = Path.GetDirectoryName(_keyFile);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

                if (File.Exists(_keyFile))
                {
                    var json = File.ReadAllText(_keyFile);
                    var key = JsonSerializer.Deserialize<IdentityKey>(json);
                    if (key != null) return key;
                }
            }
            catch { }

            var newKey = IdentityKey.Generate();
            try
            {
                var json = JsonSerializer.Serialize(newKey, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_keyFile, json);
            }
            catch { }

            return newKey;
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

                // If connecting over secure WSS without standard validation check in local dev
                if (serverUrl.StartsWith("ws://127.0.0.1") || serverUrl.StartsWith("ws://localhost"))
                {
                    // standard ws
                }

                await _webSocket.ConnectAsync(new Uri(serverUrl), _cts.Token);

                // Register with Relay
                var regPacket = new ProtocolPacket
                {
                    Type = "register",
                    Fingerprint = _myKey.Fingerprint,
                    PublicKey = _myKey.PublicKeyBase64
                };
                await SendJsonAsync(regPacket);

                StatusDot.Fill = new SolidColorBrush(Color.Parse("#2ECC71"));
                StatusText.Text = "Connected";
                ConnectBtn.Content = "Disconnect";
                ConnectBtn.IsEnabled = true;
                AddSystemMessage($"Connected to {serverUrl} via native ClientWebSocket.");

                _ = ReceiveLoopAsync(_webSocket, _cts.Token);
            }
            catch (Exception ex)
            {
                StatusDot.Fill = new SolidColorBrush(Color.Parse("#FF4D4D"));
                StatusText.Text = "Connection Failed";
                ConnectBtn.IsEnabled = true;
                AddSystemMessage($"Error: {ex.Message}");
            }
        }

        private async Task DisconnectAsync()
        {
            try
            {
                _cts?.Cancel();
                if (_webSocket != null && _webSocket.State == WebSocketState.Open)
                {
                    await _webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closed by user", CancellationToken.None);
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
                AddSystemMessage("Disconnected from server.");
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
                        AddSystemMessage($"Receive loop terminated: {ex.Message}");
                        _ = DisconnectAsync();
                    });
                }
            }
        }

        private Task ProcessIncomingPacketAsync(ProtocolPacket packet)
        {
            Dispatcher.UIThread.Post(() =>
            {
                switch (packet.Type)
                {
                    case "message":
                        if (packet.Envelope != null)
                        {
                            try
                            {
                                var decrypted = E2eeEngine.Decrypt(packet.Envelope, _myKey);
                                var senderFp = packet.Envelope.SenderFingerprint;
                                var shortSender = senderFp[..Math.Min(8, senderFp.Length)];

                                _messages.Add(new ChatMessage
                                {
                                    Header = $"From: {shortSender}...",
                                    Text = decrypted,
                                    Time = DateTime.Now.ToString("HH:mm"),
                                    BackgroundColor = new SolidColorBrush(Color.Parse("#232D3F")),
                                    Alignment = HorizontalAlignment.Left
                                });
                            }
                            catch (Exception ex)
                            {
                                AddSystemMessage($"[E2EE Decrypt Error]: {ex.Message}");
                            }
                        }
                        break;

                    case "status":
                        AddSystemMessage($"Server status: {packet.Status}");
                        break;
                }
            });

            return Task.CompletedTask;
        }

        private async void OnSendClicked(object? sender, RoutedEventArgs e)
        {
            await SendCurrentMessageAsync();
        }

        private async void OnMessageInputKeyDown(object? sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                await SendCurrentMessageAsync();
            }
        }

        private async Task SendCurrentMessageAsync()
        {
            var text = MessageInputBox.Text?.Trim();
            if (string.IsNullOrEmpty(text)) return;

            if (_webSocket == null || _webSocket.State != WebSocketState.Open)
            {
                AddSystemMessage("Cannot send: not connected to relay server.");
                return;
            }

            var recipientId = RecipientIdBox.Text?.Trim();
            var recipientPubKey = RecipientPubKeyBox.Text?.Trim();

            if (string.IsNullOrEmpty(recipientId) || string.IsNullOrEmpty(recipientPubKey))
            {
                AddSystemMessage("Please enter Recipient ID and Recipient Public Key first.");
                return;
            }

            try
            {
                // Encrypt message using AES-256-GCM + ECDH P-256
                var envelope = E2eeEngine.Encrypt(text, recipientPubKey, _myKey, recipientId);

                var packet = new ProtocolPacket
                {
                    Type = "send",
                    Envelope = envelope
                };

                await SendJsonAsync(packet);

                _messages.Add(new ChatMessage
                {
                    Header = "Me",
                    Text = text,
                    Time = DateTime.Now.ToString("HH:mm"),
                    BackgroundColor = new SolidColorBrush(Color.Parse("#2B5278")),
                    Alignment = HorizontalAlignment.Right
                });

                MessageInputBox.Text = string.Empty;
            }
            catch (Exception ex)
            {
                AddSystemMessage($"[Encryption Error]: {ex.Message}");
            }
        }

        private async Task SendJsonAsync(ProtocolPacket packet)
        {
            if (_webSocket == null || _webSocket.State != WebSocketState.Open) return;
            var json = JsonSerializer.Serialize(packet);
            var bytes = Encoding.UTF8.GetBytes(json);
            await _webSocket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, CancellationToken.None);
        }

        private void OnCopyIdClicked(object? sender, RoutedEventArgs e)
        {
            if (Clipboard != null)
            {
                _ = Clipboard.SetTextAsync(_myKey.Fingerprint);
                AddSystemMessage("Copied Fingerprint to Clipboard!");
            }
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
