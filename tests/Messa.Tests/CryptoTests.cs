using System.Security.Cryptography;
using Messa.Core.Crypto;
using Xunit;

namespace Messa.Tests
{
    public class CryptoTests
    {
        [Fact]
        public void KeyGeneration_ShouldCreateValidKeysAndFingerprint()
        {
            var key = IdentityKey.Generate();
            Assert.NotNull(key);
            Assert.Equal(64, key.Fingerprint.Length);
            Assert.False(string.IsNullOrEmpty(key.PublicKeyBase64));
            Assert.False(string.IsNullOrEmpty(key.PrivateKeyBase64));
        }

        [Fact]
        public void E2EE_EncryptDecrypt_ShouldMatchOriginalText()
        {
            var aliceKey = IdentityKey.Generate();
            var bobKey = IdentityKey.Generate();

            var originalText = "Top-secret sovereign test message 🔒 12345";
            var envelope = E2eeEngine.Encrypt(originalText, bobKey.PublicKeyBase64, aliceKey, bobKey.Fingerprint);

            Assert.NotNull(envelope);
            Assert.Equal(bobKey.Fingerprint, envelope.RecipientFingerprint);
            Assert.Equal(aliceKey.Fingerprint, envelope.SenderFingerprint);

            var decrypted = E2eeEngine.Decrypt(envelope, bobKey);
            Assert.Equal(originalText, decrypted);
        }

        [Fact]
        public void E2EE_TamperedCiphertext_ShouldThrowCryptographicException()
        {
            var aliceKey = IdentityKey.Generate();
            var bobKey = IdentityKey.Generate();

            var envelope = E2eeEngine.Encrypt("Secret data", bobKey.PublicKeyBase64, aliceKey, bobKey.Fingerprint);
            
            // Tamper ciphertext
            var bytes = Convert.FromBase64String(envelope.CiphertextBase64);
            bytes[0] ^= 0xFF;
            envelope.CiphertextBase64 = Convert.ToBase64String(bytes);

            Assert.ThrowsAny<CryptographicException>(() => E2eeEngine.Decrypt(envelope, bobKey));
        }
    }
}
