using System.Text.Json.Serialization;
using Messa.Core.Crypto;

namespace Messa.Core.Models
{
    public class ProtocolPacket
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        [JsonPropertyName("fingerprint")]
        public string? Fingerprint { get; set; }

        [JsonPropertyName("username")]
        public string? Username { get; set; }

        [JsonPropertyName("query")]
        public string? Query { get; set; }

        [JsonPropertyName("bundle")]
        public PreKeyBundle? Bundle { get; set; }

        [JsonPropertyName("ratchetMessage")]
        public RatchetMessage? RatchetMessage { get; set; }

        [JsonPropertyName("senderIdDhKey")]
        public string? SenderIdentityDhKeyBase64 { get; set; }

        [JsonPropertyName("error")]
        public string? Error { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }
    }
}
