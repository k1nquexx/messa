using System.Collections.Generic;
using System.Text.Json.Serialization;
using Messa.Core.Crypto;

namespace Messa.Core.Models
{
    public class ProtocolPacket
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        // Device & Multi-Device Session
        [JsonPropertyName("deviceId")]
        public string? DeviceId { get; set; }

        // Identity & Search
        [JsonPropertyName("fingerprint")]
        public string? Fingerprint { get; set; }

        [JsonPropertyName("username")]
        public string? Username { get; set; }

        [JsonPropertyName("query")]
        public string? Query { get; set; }

        [JsonPropertyName("profile")]
        public UserProfile? Profile { get; set; }

        [JsonPropertyName("searchResults")]
        public List<UserProfile>? SearchResults { get; set; }

        // Challenge-Response Handshake
        [JsonPropertyName("nonce")]
        public string? Nonce { get; set; }

        [JsonPropertyName("signingPublicKey")]
        public string? SigningPublicKey { get; set; }

        [JsonPropertyName("signature")]
        public string? Signature { get; set; }

        // 2FA SRP-6a
        [JsonPropertyName("twoFactorSalt")]
        public string? TwoFactorSalt { get; set; }

        [JsonPropertyName("twoFactorB")]
        public string? TwoFactorB { get; set; }

        [JsonPropertyName("twoFactorA")]
        public string? TwoFactorA { get; set; }

        [JsonPropertyName("twoFactorProof")]
        public string? TwoFactorProof { get; set; }

        [JsonPropertyName("enable2FA")]
        public bool? Enable2FA { get; set; }

        // Telegram-style Multi-Device PTS Sync
        [JsonPropertyName("pts")]
        public long? Pts { get; set; }

        [JsonPropertyName("fromPts")]
        public long? FromPts { get; set; }

        [JsonPropertyName("currentPts")]
        public long? CurrentPts { get; set; }

        [JsonPropertyName("cloudMessage")]
        public CloudMessage? CloudMessage { get; set; }

        [JsonPropertyName("difference")]
        public List<CloudMessage>? Difference { get; set; }

        // Delivery & Read Receipts Tracking
        [JsonPropertyName("messageId")]
        public string? MessageId { get; set; }

        [JsonPropertyName("chatId")]
        public string? ChatId { get; set; }

        [JsonPropertyName("deliveryStatus")]
        public MessageDeliveryStatus? DeliveryStatus { get; set; }

        // Pre-Key Bundle & Double Ratchet
        [JsonPropertyName("bundle")]
        public PreKeyBundle? Bundle { get; set; }

        [JsonPropertyName("ratchetMessage")]
        public RatchetMessage? RatchetMessage { get; set; }

        [JsonPropertyName("senderIdDhKey")]
        public string? SenderIdentityDhKeyBase64 { get; set; }

        // General
        [JsonPropertyName("error")]
        public string? Error { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }
    }
}
