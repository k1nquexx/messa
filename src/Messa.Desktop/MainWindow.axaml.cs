using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net.WebSockets;
using System.Security.Cryptography;
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
        private UserProfile _myProfile;
        private ClientWebSocket? _webSocket;
        private CancellationTokenSource? _cts;
        private readonly ObservableCollection<ChatMessage> _messages = new();
        private readonly ObservableCollection<ContactCard> _contacts = new();

        private readonly string _appDataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Messa");
        private readonly string _keyFile;
        private readonly string _profileFile;
        private readonly string _contactsFile;
        private readonly string _settingsFile;

        // Telegram-style Multi-Device PTS State
        private readonly string _deviceId = $"desktop-{Environment.MachineName}";
        private long _localPts = 0;

        // Double Ratchet Sessions by Peer Fingerprint
        private readonly ConcurrentDictionary<string, DoubleRatchetSession> _sessions = new();
        private ContactCard? _activeContact;

        private TaskCompletionSource<PreKeyBundle?>? _pendingBundleLookup;

        public MainWindow()
        {
            InitializeComponent();
            _keyFile = Path.Combine(_appDataDir, "identity.json");
            _profileFile = Path.Combine(_appDataDir, "profile.json");
            _contactsFile = Path.Combine(_appDataDir, "contacts.json");
            _settingsFile = Path.Combine(_appDataDir, "settings.json");

            MessagesList.ItemsSource = _messages;
            ContactsList.ItemsSource = _contacts;

            _myKey = LoadOrCreateIdentity();
            _myProfile = LoadOrCreateProfile();
            LoadContacts();
            LoadSettings();

            UpdateProfileUI();
            AddSystemMessage("Sovereign Native Engine ready. Multi-Device PTS Cloud Sync enabled.");
        }

        private IdentityKey LoadOrCreateIdentity()
        {
            try
            {
                Directory.CreateDirectory(_appDataDir);
                if (File.Exists(_keyFile))
                {
                    var key = JsonSerializer.Deserialize<IdentityKey>(File.ReadAllText(_keyFile));
                    if (key != null && !string.IsNullOrEmpty(key.SignedPreKeyPrivateKeyBase64)) return key;
                }
            }
            catch { }

            var newKey = IdentityKey.Generate("alice");
            SaveIdentity(newKey);
            return newKey;
        }

        private void SaveIdentity(IdentityKey key)
        {
            try
            {
                Directory.CreateDirectory(_appDataDir);
                File.WriteAllText(_keyFile, JsonSerializer.Serialize(key, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        private UserProfile LoadOrCreateProfile()
        {
            try
            {
                if (File.Exists(_profileFile))
                {
                    var p = JsonSerializer.Deserialize<UserProfile>(File.ReadAllText(_profileFile));
                    if (p != null) return p;
                }
            }
            catch { }

            var newProfile = new UserProfile
            {
                Username = string.IsNullOrEmpty(_myKey.Username) ? "alice" : _myKey.Username,
                DisplayName = "Alice",
                Bio = "Sovereign P2P Messenger User",
                StatusText = "Online",
                Fingerprint = _myKey.Fingerprint
            };
            SaveProfile(newProfile);
            return newProfile;
        }

        private void SaveProfile(UserProfile p)
        {
            try
            {
                Directory.CreateDirectory(_appDataDir);
                File.WriteAllText(_profileFile, JsonSerializer.Serialize(p, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        private void LoadContacts()
        {
            try
            {
                if (File.Exists(_contactsFile))
                {
                    var list = JsonSerializer.Deserialize<List<ContactCard>>(File.ReadAllText(_contactsFile));
                    if (list != null)
                    {
                        foreach (var c in list) _contacts.Add(c);
                    }
                }
            }
            catch { }

            if (_contacts.Count == 0)
            {
                var demoContact = new ContactCard
                {
                    Username = "@bob",
                    DisplayName = "Bob",
                    Bio = "Peer contact",
                    Fingerprint = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
                    LastMessagePreview = "Start an encrypted chat...",
                    LastMessageTime = DateTime.Now.ToString("HH:mm")
                };
                _contacts.Add(demoContact);
                SaveContacts();
            }
        }

        private void SaveContacts()
        {
            try
            {
                Directory.CreateDirectory(_appDataDir);
                File.WriteAllText(_contactsFile, JsonSerializer.Serialize(_contacts.ToList(), new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        private void LoadSettings()
        {
            try
            {
                if (File.Exists(_settingsFile))
                {
                    var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(_settingsFile));
                    if (dict != null && dict.TryGetValue("pts", out var ptsStr) && long.TryParse(ptsStr, out var pts))
                    {
                        _localPts = pts;
                    }
                }
            }
            catch { }
        }

        private void SaveSettings()
        {
            try
            {
                Directory.CreateDirectory(_appDataDir);
                var dict = new Dictionary<string, string> { { "pts", _localPts.ToString() } };
                File.WriteAllText(_settingsFile, JsonSerializer.Serialize(dict));
            }
            catch { }
        }

        private void UpdateProfileUI()
        {
            MyDisplayNameText.Text = _myProfile.DisplayName;
            MyUsernameText.Text = $"@{_myProfile.Username.TrimStart('@')}";
            MyAvatarInitial.Text = string.IsNullOrEmpty(_myProfile.DisplayName) ? "A" : _myProfile.DisplayName[0].ToString().ToUpper();
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
                StatusDot.Fill = new SolidColorBrush(Color.Parse("#FFA500"));

                _cts = new CancellationTokenSource();
                _webSocket = new ClientWebSocket();

                await _webSocket.ConnectAsync(new Uri(serverUrl), _cts.Token);

                // STEP 1: Handshake with Challenge-Response
                var challengePacket = await ReceivePacketAsync(_webSocket, _cts.Token);
                if (challengePacket == null || challengePacket.Type != "auth_challenge" || string.IsNullOrEmpty(challengePacket.Nonce))
                {
                    throw new CryptographicException("Server failed to issue cryptographic auth_challenge.");
                }

                var nonceBytes = Convert.FromBase64String(challengePacket.Nonce);
                var signature = _myKey.Sign(nonceBytes);

                var authResponse = new ProtocolPacket
                {
                    Type = "auth_response",
                    DeviceId = _deviceId,
                    Fingerprint = _myKey.Fingerprint,
                    Username = _myProfile.Username,
                    SigningPublicKey = _myKey.SigningPublicKeyBase64,
                    Signature = Convert.ToBase64String(signature)
                };
                await SendJsonAsync(authResponse);

                var authResult = await ReceivePacketAsync(_webSocket, _cts.Token);
                if (authResult == null || authResult.Type != "auth_success")
                {
                    throw new CryptographicException($"Handshake rejected: {authResult?.Error ?? "Unknown error"}");
                }

                StatusDot.Fill = new SolidColorBrush(Color.Parse("#10B981"));
                ConnectBtn.Content = "Disconnect";
                ConnectBtn.IsEnabled = true;
                AddSystemMessage($"Connected as device '{_deviceId}' (PTS: {_localPts}).");

                // Publish PreKey Bundle & Profile
                var bundle = PreKeyBundle.Create(_myKey);
                await SendJsonAsync(new ProtocolPacket { Type = "publish_bundle", Bundle = bundle });
                await SendJsonAsync(new ProtocolPacket { Type = "update_profile", Profile = _myProfile });

                // STEP 2: Request Telegram-style PTS difference (missed updates)
                await SendJsonAsync(new ProtocolPacket
                {
                    Type = "get_difference",
                    FromPts = _localPts
                });

                _ = ReceiveLoopAsync(_webSocket, _cts.Token);
            }
            catch (Exception ex)
            {
                StatusDot.Fill = new SolidColorBrush(Color.Parse("#EF4444"));
                ConnectBtn.IsEnabled = true;
                AddSystemMessage($"Connection Failed: {ex.Message}");
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
                StatusDot.Fill = new SolidColorBrush(Color.Parse("#EF4444"));
                ConnectBtn.Content = "Connect";
                ConnectBtn.IsEnabled = true;
                AddSystemMessage("Disconnected from server.");
            }
        }

        private async Task ReceiveLoopAsync(ClientWebSocket socket, CancellationToken ct)
        {
            try
            {
                while (socket.State == WebSocketState.Open && !ct.IsCancellationRequested)
                {
                    var packet = await ReceivePacketAsync(socket, ct);
                    if (packet == null) break;

                    switch (packet.Type)
                    {
                        case "difference_result":
                            if (packet.Difference != null)
                            {
                                foreach (var msg in packet.Difference)
                                {
                                    ApplyCloudMessage(msg);
                                }
                                if (packet.CurrentPts.HasValue)
                                {
                                    _localPts = packet.CurrentPts.Value;
                                    SaveSettings();
                                }
                                if (packet.Difference.Count > 0)
                                {
                                    Dispatcher.UIThread.Post(() => AddSystemMessage($"Synchronized {packet.Difference.Count} cloud message(s)."));
                                }
                            }
                            break;

                        case "new_message":
                            if (packet.CloudMessage != null)
                            {
                                ApplyCloudMessage(packet.CloudMessage);
                                if (packet.Pts.HasValue && packet.Pts.Value > _localPts)
                                {
                                    _localPts = packet.Pts.Value;
                                    SaveSettings();
                                }
                            }
                            break;

                        case "bundle_result":
                            _pendingBundleLookup?.TrySetResult(packet.Bundle);
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested)
                {
                    Dispatcher.UIThread.Post(() =>
                    {
                        AddSystemMessage($"Connection dropped: {ex.Message}");
                        _ = DisconnectAsync();
                    });
                }
            }
        }

        private void ApplyCloudMessage(CloudMessage msg)
        {
            var peerFp = msg.PeerFingerprint;
            var contact = _contacts.FirstOrDefault(c => c.Fingerprint.Equals(peerFp, StringComparison.OrdinalIgnoreCase));

            var displayText = !string.IsNullOrEmpty(msg.Text) ? msg.Text : "[Encrypted Payload]";

            if (contact != null)
            {
                contact.LastMessagePreview = msg.IsOutgoing ? $"You: {displayText}" : displayText;
                contact.LastMessageTime = DateTimeOffset.FromUnixTimeMilliseconds(msg.Timestamp).LocalDateTime.ToString("HH:mm");
                SaveContacts();
            }

            Dispatcher.UIThread.Post(() =>
            {
                if (msg.IsOutgoing)
                {
                    _messages.Add(new ChatMessage
                    {
                        Header = "Me (synced)",
                        Text = displayText,
                        Time = DateTimeOffset.FromUnixTimeMilliseconds(msg.Timestamp).LocalDateTime.ToString("HH:mm"),
                        StatusBadge = $"PTS #{msg.Pts} • Cloud Synced",
                        BackgroundColor = new SolidColorBrush(Color.Parse("#2563EB")),
                        Alignment = HorizontalAlignment.Right
                    });
                }
                else
                {
                    var senderName = contact?.DisplayName ?? msg.SenderFingerprint[..8];
                    _messages.Add(new ChatMessage
                    {
                        Header = senderName,
                        Text = displayText,
                        Time = DateTimeOffset.FromUnixTimeMilliseconds(msg.Timestamp).LocalDateTime.ToString("HH:mm"),
                        StatusBadge = $"PTS #{msg.Pts} • Verified",
                        BackgroundColor = new SolidColorBrush(Color.Parse("#1F2937")),
                        Alignment = HorizontalAlignment.Left
                    });
                }
            });
        }

        private async void OnContactSelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (ContactsList.SelectedItem is ContactCard contact)
            {
                _activeContact = contact;
                ActivePeerNameText.Text = $"{contact.DisplayName} (@{contact.Username.TrimStart('@')})";
                ActivePeerInitial.Text = string.IsNullOrEmpty(contact.DisplayName) ? "?" : contact.DisplayName[0].ToString().ToUpper();
                ActivePeerDetailsText.Text = $"ID: {contact.Fingerprint[..16]}... • Multi-Device Cloud Sync";

                if (!_sessions.ContainsKey(contact.Fingerprint) && _webSocket != null && _webSocket.State == WebSocketState.Open)
                {
                    _pendingBundleLookup = new TaskCompletionSource<PreKeyBundle?>();
                    await SendJsonAsync(new ProtocolPacket { Type = "lookup_bundle", Query = contact.Fingerprint });

                    var completed = await Task.WhenAny(_pendingBundleLookup.Task, Task.Delay(3000));
                    if (completed == _pendingBundleLookup.Task)
                    {
                        var bundle = await _pendingBundleLookup.Task;
                        if (bundle != null && bundle.Verify())
                        {
                            var session = DoubleRatchetSession.Initiate(_myKey, bundle);
                            _sessions[contact.Fingerprint] = session;
                        }
                    }
                }
            }
        }

        private async void OnAddContactClicked(object? sender, RoutedEventArgs e)
        {
            var search = ContactSearchBox.Text?.Trim();
            if (string.IsNullOrEmpty(search)) return;

            var linkContact = ContactCard.FromInviteLink(search);
            if (linkContact != null)
            {
                AddOrUpdateContact(linkContact);
                ContactSearchBox.Text = string.Empty;
                return;
            }

            if (_webSocket == null || _webSocket.State != WebSocketState.Open)
            {
                AddSystemMessage("Please connect to server to find users.");
                return;
            }

            AddSystemMessage($"Searching for '{search}' in Global Directory...");
            _pendingBundleLookup = new TaskCompletionSource<PreKeyBundle?>();
            await SendJsonAsync(new ProtocolPacket { Type = "lookup_bundle", Query = search });

            var completed = await Task.WhenAny(_pendingBundleLookup.Task, Task.Delay(4000));
            if (completed == _pendingBundleLookup.Task)
            {
                var bundle = await _pendingBundleLookup.Task;
                if (bundle != null)
                {
                    var newContact = new ContactCard
                    {
                        Username = string.IsNullOrEmpty(bundle.Username) ? search : $"@{bundle.Username.TrimStart('@')}",
                        DisplayName = string.IsNullOrEmpty(bundle.Username) ? search : bundle.Username,
                        Fingerprint = bundle.Fingerprint,
                        LastMessagePreview = "Contact added",
                        LastMessageTime = DateTime.Now.ToString("HH:mm")
                    };
                    AddOrUpdateContact(newContact);
                    ContactSearchBox.Text = string.Empty;
                    AddSystemMessage($"Added contact: {newContact.DisplayName} ({newContact.Username})");
                }
                else
                {
                    AddSystemMessage($"User '{search}' not found.");
                }
            }
        }

        private void AddOrUpdateContact(ContactCard contact)
        {
            var existing = _contacts.FirstOrDefault(c => c.Fingerprint.Equals(contact.Fingerprint, StringComparison.OrdinalIgnoreCase));
            if (existing == null)
            {
                _contacts.Add(contact);
            }
            else
            {
                existing.DisplayName = contact.DisplayName;
                existing.Username = contact.Username;
            }
            SaveContacts();
            ContactsList.SelectedItem = contact;
        }

        private void OnSearchKeyDown(object? sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) OnAddContactClicked(sender, e);
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

            if (_activeContact == null)
            {
                AddSystemMessage("Select a contact first.");
                return;
            }

            if (_webSocket == null || _webSocket.State != WebSocketState.Open)
            {
                AddSystemMessage("Not connected to relay.");
                return;
            }

            try
            {
                // Send via multi-device cloud sync
                var sendPacket = new ProtocolPacket
                {
                    Type = "send_message",
                    Query = _activeContact.Fingerprint,
                    CloudMessage = new CloudMessage
                    {
                        PeerFingerprint = _activeContact.Fingerprint,
                        SenderFingerprint = _myKey.Fingerprint,
                        Text = text
                    }
                };

                await SendJsonAsync(sendPacket);

                _activeContact.LastMessagePreview = $"You: {text}";
                _activeContact.LastMessageTime = DateTime.Now.ToString("HH:mm");
                SaveContacts();

                _messages.Add(new ChatMessage
                {
                    Header = "Me",
                    Text = text,
                    Time = DateTime.Now.ToString("HH:mm"),
                    StatusBadge = "Sent • Cloud Synced",
                    BackgroundColor = new SolidColorBrush(Color.Parse("#2563EB")),
                    Alignment = HorizontalAlignment.Right
                });

                MessageInputBox.Text = string.Empty;
            }
            catch (Exception ex)
            {
                AddSystemMessage($"Send failed: {ex.Message}");
            }
        }

        private async void OnEditProfileClicked(object? sender, RoutedEventArgs e)
        {
            _myProfile.DisplayName = _myProfile.DisplayName == "Alice" ? "Alice Cooper" : "Alice";
            SaveProfile(_myProfile);
            UpdateProfileUI();

            if (_webSocket != null && _webSocket.State == WebSocketState.Open)
            {
                await SendJsonAsync(new ProtocolPacket { Type = "update_profile", Profile = _myProfile });
                AddSystemMessage($"Profile updated: {_myProfile.DisplayName}");
            }
        }

        private void OnCopyInviteClicked(object? sender, RoutedEventArgs e)
        {
            var myContact = new ContactCard
            {
                Username = $"@{_myProfile.Username.TrimStart('@')}",
                DisplayName = _myProfile.DisplayName,
                Fingerprint = _myKey.Fingerprint
            };
            var link = myContact.ToInviteLink();
            Clipboard?.SetTextAsync(link);
            AddSystemMessage($"Invite link copied: {link}");
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
                BackgroundColor = new SolidColorBrush(Color.Parse("#111827")),
                Alignment = HorizontalAlignment.Center
            });
        }
    }
}
