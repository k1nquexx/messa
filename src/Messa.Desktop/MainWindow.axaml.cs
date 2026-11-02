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

        // Double Ratchet Sessions by Peer Fingerprint
        private readonly ConcurrentDictionary<string, DoubleRatchetSession> _sessions = new();
        private ContactCard? _activeContact;

        // Pending lookup tasks
        private TaskCompletionSource<PreKeyBundle?>? _pendingBundleLookup;
        private TaskCompletionSource<List<UserProfile>?>? _pendingSearch;

        public MainWindow()
        {
            InitializeComponent();
            _keyFile = Path.Combine(_appDataDir, "identity.json");
            _profileFile = Path.Combine(_appDataDir, "profile.json");
            _contactsFile = Path.Combine(_appDataDir, "contacts.json");

            MessagesList.ItemsSource = _messages;
            ContactsList.ItemsSource = _contacts;

            _myKey = LoadOrCreateIdentity();
            _myProfile = LoadOrCreateProfile();
            LoadContacts();

            UpdateProfileUI();
            AddSystemMessage("Sovereign Native Engine ready. Challenge-Response & Double Ratchet active.");
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
                // Default saved contact for demo
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

                // Sign challenge nonce using ECDSA P-256 private key
                var nonceBytes = Convert.FromBase64String(challengePacket.Nonce);
                var signature = _myKey.Sign(nonceBytes);

                var authResponse = new ProtocolPacket
                {
                    Type = "auth_response",
                    Fingerprint = _myKey.Fingerprint,
                    Username = _myProfile.Username,
                    SigningPublicKey = _myKey.SigningPublicKeyBase64,
                    Signature = Convert.ToBase64String(signature)
                };
                await SendJsonAsync(authResponse);

                var authResult = await ReceivePacketAsync(_webSocket, _cts.Token);
                if (authResult == null || authResult.Type != "auth_success")
                {
                    throw new CryptographicException($"Handshake authentication rejected: {authResult?.Error ?? "Unknown error"}");
                }

                StatusDot.Fill = new SolidColorBrush(Color.Parse("#10B981"));
                ConnectBtn.Content = "Disconnect";
                ConnectBtn.IsEnabled = true;
                AddSystemMessage($"Cryptographically authenticated on {serverUrl} via ECDSA Nonce Signature!");

                // Publish PreKey Bundle
                var bundle = PreKeyBundle.Create(_myKey);
                await SendJsonAsync(new ProtocolPacket { Type = "publish_bundle", Bundle = bundle });

                // Publish User Profile
                await SendJsonAsync(new ProtocolPacket { Type = "update_profile", Profile = _myProfile });

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
                        case "bundle_result":
                            _pendingBundleLookup?.TrySetResult(packet.Bundle);
                            break;

                        case "search_results":
                            _pendingSearch?.TrySetResult(packet.SearchResults);
                            break;

                        case "ratchet_message":
                            if (packet.RatchetMessage != null)
                            {
                                await HandleIncomingRatchetMessageAsync(packet);
                            }
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
                        AddSystemMessage($"Connection error: {ex.Message}");
                        _ = DisconnectAsync();
                    });
                }
            }
        }

        private async Task HandleIncomingRatchetMessageAsync(ProtocolPacket packet)
        {
            var msg = packet.RatchetMessage!;
            var senderFp = msg.SenderFingerprint;

            if (!_sessions.TryGetValue(senderFp, out var session))
            {
                // Fetch sender's prekey bundle
                _pendingBundleLookup = new TaskCompletionSource<PreKeyBundle?>();
                await SendJsonAsync(new ProtocolPacket { Type = "lookup_bundle", Query = senderFp });

                var senderBundle = await _pendingBundleLookup.Task;
                if (senderBundle == null || !senderBundle.Verify())
                {
                    Dispatcher.UIThread.Post(() => AddSystemMessage("Received message from unverifiable sender!"));
                    return;
                }

                session = DoubleRatchetSession.Accept(
                    _myKey,
                    senderFp,
                    senderBundle.IdentitySigningKeyBase64,
                    packet.SenderIdentityDhKeyBase64 ?? senderBundle.IdentityDhKeyBase64,
                    Convert.FromBase64String(msg.DhPublicKeyBase64));

                _sessions[senderFp] = session;
            }

            try
            {
                var decrypted = session.Decrypt(msg);

                // Update contact preview in list
                var contact = _contacts.FirstOrDefault(c => c.Fingerprint.Equals(senderFp, StringComparison.OrdinalIgnoreCase));
                if (contact != null)
                {
                    contact.LastMessagePreview = decrypted;
                    contact.LastMessageTime = DateTime.Now.ToString("HH:mm");
                    SaveContacts();
                }

                Dispatcher.UIThread.Post(() =>
                {
                    var senderName = contact?.DisplayName ?? senderFp[..8];
                    _messages.Add(new ChatMessage
                    {
                        Header = senderName,
                        Text = decrypted,
                        Time = DateTime.Now.ToString("HH:mm"),
                        StatusBadge = $"Verified ECDSA • Ratchet #{msg.MessageNumber}",
                        BackgroundColor = new SolidColorBrush(Color.Parse("#1F2937")),
                        Alignment = HorizontalAlignment.Left
                    });
                });
            }
            catch (Exception ex)
            {
                Dispatcher.UIThread.Post(() => AddSystemMessage($"Security Error on incoming message: {ex.Message}"));
            }
        }

        private async void OnContactSelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (ContactsList.SelectedItem is ContactCard contact)
            {
                _activeContact = contact;
                ActivePeerNameText.Text = $"{contact.DisplayName} (@{contact.Username.TrimStart('@')})";
                ActivePeerInitial.Text = string.IsNullOrEmpty(contact.DisplayName) ? "?" : contact.DisplayName[0].ToString().ToUpper();
                ActivePeerDetailsText.Text = $"ID: {contact.Fingerprint[..16]}... • Double Ratchet E2EE";

                // Ensure Double Ratchet session exists
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
                            AddSystemMessage($"Ratchet session ready with {contact.DisplayName} 🔒");
                        }
                    }
                }
            }
        }

        private async void OnAddContactClicked(object? sender, RoutedEventArgs e)
        {
            var search = ContactSearchBox.Text?.Trim();
            if (string.IsNullOrEmpty(search)) return;

            // Check if it's an invite link
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

            if (!_sessions.TryGetValue(_activeContact.Fingerprint, out var session))
            {
                // Init session on the fly
                _pendingBundleLookup = new TaskCompletionSource<PreKeyBundle?>();
                await SendJsonAsync(new ProtocolPacket { Type = "lookup_bundle", Query = _activeContact.Fingerprint });
                var bundle = await _pendingBundleLookup.Task;
                if (bundle != null && bundle.Verify())
                {
                    session = DoubleRatchetSession.Initiate(_myKey, bundle);
                    _sessions[_activeContact.Fingerprint] = session;
                }
                else
                {
                    AddSystemMessage("Cannot initiate Double Ratchet with recipient.");
                    return;
                }
            }

            try
            {
                // Encrypt with Double Ratchet + sign with ECDSA
                var msg = session.Encrypt(text, _myKey);
                var packet = new ProtocolPacket
                {
                    Type = "ratchet_message",
                    RatchetMessage = msg,
                    SenderIdentityDhKeyBase64 = _myKey.DhPublicKeyBase64
                };
                await SendJsonAsync(packet);

                // Update contact preview
                _activeContact.LastMessagePreview = $"You: {text}";
                _activeContact.LastMessageTime = DateTime.Now.ToString("HH:mm");
                SaveContacts();

                _messages.Add(new ChatMessage
                {
                    Header = "Me",
                    Text = text,
                    Time = DateTime.Now.ToString("HH:mm"),
                    StatusBadge = $"Signed ECDSA • Ratchet #{msg.MessageNumber}",
                    BackgroundColor = new SolidColorBrush(Color.Parse("#2563EB")),
                    Alignment = HorizontalAlignment.Right
                });

                MessageInputBox.Text = string.Empty;
            }
            catch (Exception ex)
            {
                AddSystemMessage($"Encryption failed: {ex.Message}");
            }
        }

        private async void OnEditProfileClicked(object? sender, RoutedEventArgs e)
        {
            // Simple inline profile update
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
            AddSystemMessage($"Invite link copied to clipboard: {link}");
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
