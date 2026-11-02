using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using Messa.Core.Models;

namespace Messa.Core.Storage
{
    public class PtsMessageStore
    {
        private readonly string _storeFile;
        private readonly ConcurrentDictionary<string, long> _ptsByAccount = new();
        private readonly ConcurrentDictionary<string, List<CloudMessage>> _messagesByAccount = new();
        private readonly object _saveLock = new();

        public PtsMessageStore(string dataDir)
        {
            _storeFile = Path.Combine(dataDir, "cloud_messages.json");
            LoadFromDisk();
        }

        public (CloudMessage aliceMsg, CloudMessage bobMsg) StoreAndSequenceMessage(
            string senderFp,
            string recipientFp,
            string ciphertext,
            string tag,
            string iv,
            string signature,
            string plainText = "")
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // 1. Sequence for Recipient
            var recipientPts = _ptsByAccount.AddOrUpdate(recipientFp, 1, (_, current) => current + 1);
            var recipientMsg = new CloudMessage
            {
                Id = Guid.NewGuid().ToString("N"),
                OwnerFingerprint = recipientFp,
                PeerFingerprint = senderFp,
                SenderFingerprint = senderFp,
                Pts = recipientPts,
                IsOutgoing = false,
                CiphertextBase64 = ciphertext,
                TagBase64 = tag,
                IvBase64 = iv,
                SignatureBase64 = signature,
                Text = plainText,
                Timestamp = now
            };

            AddMessageInternal(recipientFp, recipientMsg);

            // 2. Sequence for Sender (multi-device sync echo)
            var senderPts = _ptsByAccount.AddOrUpdate(senderFp, 1, (_, current) => current + 1);
            var senderMsg = new CloudMessage
            {
                Id = Guid.NewGuid().ToString("N"),
                OwnerFingerprint = senderFp,
                PeerFingerprint = recipientFp,
                SenderFingerprint = senderFp,
                Pts = senderPts,
                IsOutgoing = true,
                CiphertextBase64 = ciphertext,
                TagBase64 = tag,
                IvBase64 = iv,
                SignatureBase64 = signature,
                Text = plainText,
                Timestamp = now
            };

            AddMessageInternal(senderFp, senderMsg);

            SaveToDiskAsync();
            return (recipientMsg, senderMsg);
        }

        public (List<CloudMessage> messages, long currentPts) GetDifference(string accountFp, long fromPts, int limit = 100)
        {
            _ptsByAccount.TryGetValue(accountFp, out var currentPts);

            if (!_messagesByAccount.TryGetValue(accountFp, out var list))
            {
                return (new List<CloudMessage>(), currentPts);
            }

            List<CloudMessage> result;
            lock (list)
            {
                result = list
                    .Where(m => m.Pts > fromPts)
                    .OrderBy(m => m.Pts)
                    .Take(limit)
                    .ToList();
            }

            return (result, currentPts);
        }

        public long GetCurrentPts(string accountFp)
        {
            _ptsByAccount.TryGetValue(accountFp, out var pts);
            return pts;
        }

        private void AddMessageInternal(string accountFp, CloudMessage msg)
        {
            var list = _messagesByAccount.GetOrAdd(accountFp, _ => new List<CloudMessage>());
            lock (list)
            {
                list.Add(msg);
            }
        }

        private void LoadFromDisk()
        {
            if (File.Exists(_storeFile))
            {
                try
                {
                    var json = File.ReadAllText(_storeFile);
                    var dict = JsonSerializer.Deserialize<Dictionary<string, List<CloudMessage>>>(json);
                    if (dict != null)
                    {
                        foreach (var kvp in dict)
                        {
                            _messagesByAccount[kvp.Key] = kvp.Value;
                            var maxPts = kvp.Value.Count > 0 ? kvp.Value.Max(m => m.Pts) : 0;
                            _ptsByAccount[kvp.Key] = maxPts;
                        }
                    }
                }
                catch { }
            }
        }

        private void SaveToDiskAsync()
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                lock (_saveLock)
                {
                    try
                    {
                        var copy = new Dictionary<string, List<CloudMessage>>();
                        foreach (var kvp in _messagesByAccount)
                        {
                            lock (kvp.Value)
                            {
                                copy[kvp.Key] = new List<CloudMessage>(kvp.Value);
                            }
                        }
                        var json = JsonSerializer.Serialize(copy, new JsonSerializerOptions { WriteIndented = true });
                        File.WriteAllText(_storeFile, json);
                    }
                    catch { }
                }
            });
        }
    }
}
