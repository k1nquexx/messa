using System;
using System.Text.Json.Serialization;

namespace Messa.Core.Crypto
{
    public class PreKeyBundle
    {
        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty;

        [JsonPropertyName("fingerprint")]
        public string Fingerprint { get; set; } = string.Empty;

        [JsonPropertyName("identitySigningKey")]
        public string IdentitySigningKeyBase64 { get; set; } = string.Empty;

        [JsonPropertyName("identityDhKey")]
        public string IdentityDhKeyBase64 { get; set; } = string.Empty;

        [JsonPropertyName("signedPreKey")]
        public string SignedPreKeyBase64 { get; set; } = string.Empty;

        [JsonPropertyName("preKeySignature")]
        public string PreKeySignatureBase64 { get; set; } = string.Empty;

        [JsonPropertyName("timestamp")]
        public long Timestamp { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        public static PreKeyBundle Create(IdentityKey identity)
        {
            var preKeyPubBytes = Convert.FromBase64String(identity.SignedPreKeyPublicKeyBase64);
            var signature = identity.Sign(preKeyPubBytes);

            return new PreKeyBundle
            {
                Username = identity.Username,
                Fingerprint = identity.Fingerprint,
                IdentitySigningKeyBase64 = identity.SigningPublicKeyBase64,
                IdentityDhKeyBase64 = identity.DhPublicKeyBase64,
                SignedPreKeyBase64 = identity.SignedPreKeyPublicKeyBase64,
                PreKeySignatureBase64 = Convert.ToBase64String(signature),
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };
        }

        public bool Verify()
        {
            try
            {
                var preKeyBytes = Convert.FromBase64String(SignedPreKeyBase64);
                var sigBytes = Convert.FromBase64String(PreKeySignatureBase64);
                return IdentityKey.VerifySignature(preKeyBytes, sigBytes, IdentitySigningKeyBase64);
            }
            catch
            {
                return false;
            }
        }
    }
}
