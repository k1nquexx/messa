using System;
using System.Text.Json.Serialization;

namespace Messa.Core.Models
{
    public enum MessageDeliveryStatus
    {
        Sent = 1,      // 1 Checkmark (Server saved & sequenced)
        Delivered = 2, // 2 Gray Checkmarks (Delivered to recipient socket)
        Read = 3       // 2 Blue/Green Checkmarks (Recipient viewed message)
    }

    public class CloudMessage
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = Guid.NewGuid().ToString("N");

        [JsonPropertyName("ownerFp")]
        public string OwnerFingerprint { get; set; } = string.Empty;

        [JsonPropertyName("peerFp")]
        public string PeerFingerprint { get; set; } = string.Empty;

        [JsonPropertyName("senderFp")]
        public string SenderFingerprint { get; set; } = string.Empty;

        [JsonPropertyName("pts")]
        public long Pts { get; set; }

        [JsonPropertyName("isOutgoing")]
        public bool IsOutgoing { get; set; }

        [JsonPropertyName("status")]
        public MessageDeliveryStatus Status { get; set; } = MessageDeliveryStatus.Sent;

        [JsonPropertyName("text")]
        public string Text { get; set; } = string.Empty;

        [JsonPropertyName("ciphertext")]
        public string CiphertextBase64 { get; set; } = string.Empty;

        [JsonPropertyName("iv")]
        public string IvBase64 { get; set; } = string.Empty;

        [JsonPropertyName("tag")]
        public string TagBase64 { get; set; } = string.Empty;

        [JsonPropertyName("signature")]
        public string SignatureBase64 { get; set; } = string.Empty;

        [JsonPropertyName("timestamp")]
        public long Timestamp { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        [JsonPropertyName("deliveredAt")]
        public long? DeliveredAt { get; set; }

        [JsonPropertyName("readAt")]
        public long? ReadAt { get; set; }
    }
}
