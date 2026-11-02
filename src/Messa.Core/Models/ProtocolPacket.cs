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

        [JsonPropertyName("publicKey")]
        public string? PublicKey { get; set; }

        [JsonPropertyName("envelope")]
        public EncryptedEnvelope? Envelope { get; set; }

        [JsonPropertyName("error")]
        public string? Error { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }
    }
}
