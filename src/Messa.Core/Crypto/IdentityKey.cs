using System;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace Messa.Core.Crypto
{
    public class IdentityKey
    {
        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty;

        [JsonPropertyName("fingerprint")]
        public string Fingerprint { get; set; } = string.Empty;

        [JsonPropertyName("signingPublicKey")]
        public string SigningPublicKeyBase64 { get; set; } = string.Empty;

        [JsonPropertyName("signingPrivateKey")]
        public string SigningPrivateKeyBase64 { get; set; } = string.Empty;

        [JsonPropertyName("dhPublicKey")]
        public string DhPublicKeyBase64 { get; set; } = string.Empty;

        [JsonPropertyName("dhPrivateKey")]
        public string DhPrivateKeyBase64 { get; set; } = string.Empty;

        [JsonPropertyName("signedPreKeyPublic")]
        public string SignedPreKeyPublicKeyBase64 { get; set; } = string.Empty;

        [JsonPropertyName("signedPreKeyPrivate")]
        public string SignedPreKeyPrivateKeyBase64 { get; set; } = string.Empty;

        public static IdentityKey Generate(string username = "")
        {
            // ECDSA P-256 for digital signatures & non-repudiation
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var signingPub = ecdsa.ExportSubjectPublicKeyInfo();
            var signingPriv = ecdsa.ExportPkcs8PrivateKey();

            // ECDH P-256 for long-term DH
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var dhPub = ecdh.ExportSubjectPublicKeyInfo();
            var dhPriv = ecdh.ExportPkcs8PrivateKey();

            // ECDH P-256 for Signed Pre-Key
            using var preKeyEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var preKeyPub = preKeyEcdh.ExportSubjectPublicKeyInfo();
            var preKeyPriv = preKeyEcdh.ExportPkcs8PrivateKey();

            // Fingerprint = SHA-256 of the ECDSA Public Signing Key
            using var sha = SHA256.Create();
            var fp = Convert.ToHexString(sha.ComputeHash(signingPub)).ToLowerInvariant();

            return new IdentityKey
            {
                Username = username,
                Fingerprint = fp,
                SigningPublicKeyBase64 = Convert.ToBase64String(signingPub),
                SigningPrivateKeyBase64 = Convert.ToBase64String(signingPriv),
                DhPublicKeyBase64 = Convert.ToBase64String(dhPub),
                DhPrivateKeyBase64 = Convert.ToBase64String(dhPriv),
                SignedPreKeyPublicKeyBase64 = Convert.ToBase64String(preKeyPub),
                SignedPreKeyPrivateKeyBase64 = Convert.ToBase64String(preKeyPriv)
            };
        }

        public byte[] Sign(byte[] data)
        {
            var privBytes = Convert.FromBase64String(SigningPrivateKeyBase64);
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(privBytes, out _);
            return ecdsa.SignData(data, HashAlgorithmName.SHA256);
        }

        public static bool VerifySignature(byte[] data, byte[] signature, string publicKeyBase64)
        {
            try
            {
                var pubBytes = Convert.FromBase64String(publicKeyBase64);
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(pubBytes, out _);
                return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
            }
            catch
            {
                return false;
            }
        }
    }
}
