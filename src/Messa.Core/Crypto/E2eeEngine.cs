using System;
using System.Security.Cryptography;
using System.Text;

namespace Messa.Core.Crypto
{
    public static class E2eeEngine
    {
        public const int NonceSize = 12;
        public const int TagSize = 16;

        public static (string ciphertext, string tag, string iv) EncryptRaw(string plaintext, byte[] key)
        {
            var plainBytes = Encoding.UTF8.GetBytes(plaintext);
            var nonce = new byte[NonceSize];
            RandomNumberGenerator.Fill(nonce);
            var ciphertext = new byte[plainBytes.Length];
            var tag = new byte[TagSize];

            using var aesGcm = new AesGcm(key, TagSize);
            aesGcm.Encrypt(nonce, plainBytes, ciphertext, tag);

            return (Convert.ToBase64String(ciphertext), Convert.ToBase64String(tag), Convert.ToBase64String(nonce));
        }

        public static string DecryptRaw(string ciphertextBase64, string tagBase64, string ivBase64, byte[] key)
        {
            var nonce = Convert.FromBase64String(ivBase64);
            var ciphertext = Convert.FromBase64String(ciphertextBase64);
            var tag = Convert.FromBase64String(tagBase64);
            var decrypted = new byte[ciphertext.Length];

            using var aesGcm = new AesGcm(key, TagSize);
            aesGcm.Decrypt(nonce, ciphertext, tag, decrypted);

            return Encoding.UTF8.GetString(decrypted);
        }
    }
}
