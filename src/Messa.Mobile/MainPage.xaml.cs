using System.Collections.ObjectModel;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Graphics;
using Messa.Core.Crypto;
using Messa.Core.Models;

namespace Messa.Mobile
{
    public class MobileChatMessage
    {
        public string Header { get; set; } = string.Empty;
        public string Text { get; set; } = string.Empty;
        public string Time { get; set; } = string.Empty;
        public Color BackgroundColor { get; set; } = Color.FromArgb("#1F2937");
        public LayoutOptions Alignment { get; set; } = LayoutOptions.Start;
    }

    public partial class MainPage : ContentPage
    {
        private IdentityKey _myKey;
        private ClientWebSocket? _webSocket;
        private CancellationTokenSource? _cts;
        private readonly ObservableCollection<MobileChatMessage> _messages = new();
        private readonly string _serverUrl = "wss://fotowaqu.ru";

        public MainPage()
        {
            InitializeComponent();
            MessagesCollectionView.ItemsSource = _messages;

            _myKey = LoadOrCreateIdentity();
            MyFingerprintLabel.Text = _myKey.Fingerprint;

            AddSystemMessage("Ready. Native .NET MAUI Android engine initialized.");
        }

        private IdentityKey LoadOrCreateIdentity()
        {
            var keyPath = Path.Combine(FileSystem.AppDataDirectory, "identity.json");
            try
            {
                if (File.Exists(keyPath))
                {
                    var json = File.ReadAllText(keyPath);
                    var key = JsonSerializer.Deserialize<IdentityKey>(json);
                    if (key != null) return key;
                }
            }
            catch { }

            var newKey = IdentityKey.Generate();
            try
            {
                var json = JsonSerializer.Serialize(newKey);
                File.WriteAllText(keyPath, json);
            }
            catch { }

            return newKey;
        }

        private async void OnConnectClicked(object sender, EventArgs e)
        {
            if (_webSocket != null && _webSocket.State == WebSocketState.Open)
            {
                await DisconnectAsync();
                return;
            }

            try
            {
                ConnectBtn.IsEnabled = false;
                StatusLabel.Text = "Connecting...";

                _cts = new CancellationTokenSource();
                _webSocket = new ClientWebSocket();

                await _webSocket.ConnectAsync(new Uri(_serverUrl), _cts.Token);

                var regPacket = new ProtocolPacket
                {
                    Type = "register",
                    Fingerprint = _myKey.Fingerprint,
                    PublicKey = _myKey.PublicKeyBase64
                };
                await SendJsonAsync(regPacket);

                StatusLabel.Text = "Online (wss://fotowaqu.ru)";
                StatusLabel.TextColor = Color.FromArgb("#2ECC71");
                ConnectBtn.Text = "Disconnect";
                ConnectBtn.IsEnabled = true;
                AddSystemMessage("Connected to sovereign relay.");

                _ = ReceiveLoopAsync(_webSocket, _cts.Token);
            }
            catch (Exception ex)
            {
                StatusLabel.Text = "Offline";
                StatusLabel.TextColor = Color.FromArgb("#FF4D4D");
                ConnectBtn.IsEnabled = true;
                AddSystemMessage($"Connection failed: {ex.Message}");
            }
        }

        private async Task DisconnectAsync()
        {
            try
            {
                _cts?.Cancel();
                if (_webSocket != null && _webSocket.State == WebSocketState.Open)
                {
                    await _webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "User disconnected", CancellationToken.None);
                }
            }
            catch { }
            finally
            {
                _webSocket?.Dispose();
                _webSocket = null;
                StatusLabel.Text = "Disconnected";
                StatusLabel.TextColor = Color.FromArgb("#7A889B");
                ConnectBtn.Text = "Connect";
                ConnectBtn.IsEnabled = true;
                AddSystemMessage("Disconnected.");
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
                            MainThread.BeginInvokeOnMainThread(() => _ = DisconnectAsync());
                            return;
                        }
                        ms.Write(buffer, 0, result.Count);
                    } while (!result.EndOfMessage);

                    var json = Encoding.UTF8.GetString(ms.ToArray());
                    var packet = JsonSerializer.Deserialize<ProtocolPacket>(json);

                    if (packet != null && packet.Type == "message" && packet.Envelope != null)
                    {
                        try
                        {
                            var decrypted = E2eeEngine.Decrypt(packet.Envelope, _myKey);
                            var senderFp = packet.Envelope.SenderFingerprint;
                            var shortSender = senderFp[..Math.Min(8, senderFp.Length)];

                            MainThread.BeginInvokeOnMainThread(() =>
                            {
                                _messages.Add(new MobileChatMessage
                                {
                                    Header = $"From: {shortSender}...",
                                    Text = decrypted,
                                    Time = DateTime.Now.ToString("HH:mm"),
                                    BackgroundColor = Color.FromArgb("#232D3F"),
                                    Alignment = LayoutOptions.Start
                                });
                            });
                        }
                        catch (Exception ex)
                        {
                            MainThread.BeginInvokeOnMainThread(() => AddSystemMessage($"Decrypt error: {ex.Message}"));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested)
                {
                    MainThread.BeginInvokeOnMainThread(() =>
                    {
                        AddSystemMessage($"Disconnected: {ex.Message}");
                        _ = DisconnectAsync();
                    });
                }
            }
        }

        private async void OnSendClicked(object sender, EventArgs e)
        {
            var text = MessageInput.Text?.Trim();
            if (string.IsNullOrEmpty(text)) return;

            if (_webSocket == null || _webSocket.State != WebSocketState.Open)
            {
                AddSystemMessage("Not connected to relay.");
                return;
            }

            // Note: Recipient key can be configured via dialog / contact list
            _messages.Add(new MobileChatMessage
            {
                Header = "Me",
                Text = text,
                Time = DateTime.Now.ToString("HH:mm"),
                BackgroundColor = Color.FromArgb("#2B5278"),
                Alignment = LayoutOptions.End
            });

            MessageInput.Text = string.Empty;
        }

        private async Task SendJsonAsync(ProtocolPacket packet)
        {
            if (_webSocket == null || _webSocket.State != WebSocketState.Open) return;
            var json = JsonSerializer.Serialize(packet);
            var bytes = Encoding.UTF8.GetBytes(json);
            await _webSocket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, CancellationToken.None);
        }

        private void AddSystemMessage(string text)
        {
            _messages.Add(new MobileChatMessage
            {
                Header = "System",
                Text = text,
                Time = DateTime.Now.ToString("HH:mm"),
                BackgroundColor = Color.FromArgb("#1A202C"),
                Alignment = LayoutOptions.Center
            });
        }
    }
}
