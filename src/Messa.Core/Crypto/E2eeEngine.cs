using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Messa.Core.Crypto
{
    public class IdentityKey
    {
        public string Fingerprint { get; set; } = string.Empty;
        public string PublicKeyBase64 { get; set; } = string.Empty;
        public string PrivateKeyBase64 { get; set; } = string.Empty;

        public static IdentityKey Generate()
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var pubBytes = ecdh.ExportSubjectPublicKeyInfo();
            var privBytes = ecdh.ExportPkcs8PrivateKey();

            var pubBase64 = Convert.ToBase64String(pubBytes);
            var privBase64 = Convert.ToBase64String(privBytes);

            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(pubBytes);
            var fp = Convert.ToHexString(hash).ToLowerInvariant();

            return new IdentityKey
            {
                Fingerprint = fp,
                PublicKeyBase64 = pubBase64,
                PrivateKeyBase64 = privBase64
            };
        }
    }

    public class EncryptedEnvelope
    {
        [JsonPropertyName("senderFingerprint")]
        public string SenderFingerprint { get; set; } = string.Empty;

        [JsonPropertyName("recipientFingerprint")]
        public string RecipientFingerprint { get; set; } = string.Empty;

        [JsonPropertyName("ephemeralPub")]
        public string EphemeralPublicKeyBase64 { get; set; } = string.Empty;

        [JsonPropertyName("iv")]
        public string IvBase64 { get; set; } = string.Empty;

        [JsonPropertyName("ciphertext")]
        public string CiphertextBase64 { get; set; } = string.Empty;

        [JsonPropertyName("tag")]
        public string TagBase64 { get; set; } = string.Empty;

        [JsonPropertyName("timestamp")]
        public long Timestamp { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    }

    public static class E2eeEngine
    {
        public const int NonceSize = 12; // 96 bits for AES-GCM
        public const int TagSize = 16;   // 128 bits for AES-GCM

        public static EncryptedEnvelope Encrypt(string plaintext, string recipientPublicKeyBase64, IdentityKey senderKey, string recipientFingerprint)
        {
            var recipientPubBytes = Convert.FromBase64String(recipientPublicKeyBase64);
            using var recipientEcdh = ECDiffieHellman.Create();
            recipientEcdh.ImportSubjectPublicKeyInfo(recipientPubBytes, out _);

            // Generate ephemeral key for forward secrecy
            using var ephemeralEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var ephemeralPubBytes = ephemeralEcdh.ExportSubjectPublicKeyInfo();

            // Derive shared secret
            var sharedSecret = ephemeralEcdh.DeriveKeyMaterial(recipientEcdh.PublicKey);

            // Hash shared secret to 256-bit AES key
            using var sha = SHA256.Create();
            var aesKey = sha.ComputeHash(sharedSecret);

            // Encrypt using AES-256-GCM
            var plainBytes = Encoding.UTF8.GetBytes(plaintext);
            var nonce = new byte[NonceSize];
            RandomNumberGenerator.Fill(nonce);

            var ciphertext = new byte[plainBytes.Length];
            var tag = new byte[TagSize];

            using var aesGcm = new AesGcm(aesKey, TagSize);
            aesGcm.Encrypt(nonce, plainBytes, ciphertext, tag);

            return new EncryptedEnvelope
            {
                SenderFingerprint = senderKey.Fingerprint,
                RecipientFingerprint = recipientFingerprint,
                EphemeralPublicKeyBase64 = Convert.ToBase64String(ephemeralPubBytes),
                IvBase64 = Convert.ToBase64String(nonce),
                CiphertextBase64 = Convert.ToBase64String(ciphertext),
                TagBase64 = Convert.ToBase64String(tag),
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };
        }

        public static string Decrypt(EncryptedEnvelope envelope, IdentityKey myKey)
        {
            var myPrivBytes = Convert.FromBase64String(myKey.PrivateKeyBase64);
            using var myEcdh = ECDiffieHellman.Create();
            myEcdh.ImportPkcs8PrivateKey(myPrivBytes, out _);

            var ephemeralPubBytes = Convert.FromBase64String(envelope.EphemeralPublicKeyBase64);
            using var ephemeralEcdh = ECDiffieHellman.Create();
            ephemeralEcdh.ImportSubjectPublicKeyInfo(ephemeralPubBytes, out _);

            // Derive shared secret
            var sharedSecret = myEcdh.DeriveKeyMaterial(ephemeralEcdh.PublicKey);

            using var sha = SHA256.Create();
            var aesKey = sha.ComputeHash(sharedSecret);

            var nonce = Convert.FromBase64String(envelope.IvBase64);
            var ciphertext = Convert.FromBase64String(envelope.CiphertextBase64);
            var tag = Convert.FromBase64String(envelope.TagBase64);
            var decryptedBytes = new byte[ciphertext.Length];

            using var aesGcm = new AesGcm(aesKey, TagSize);
            aesGcm.Decrypt(nonce, ciphertext, tag, decryptedBytes);

            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}
