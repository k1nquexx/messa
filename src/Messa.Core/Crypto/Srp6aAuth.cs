using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Messa.Core.Crypto
{
    /// <summary>
    /// RFC 5054 / Telegram style SRP-6a Zero-Knowledge Password Protocol (2048-bit Group)
    /// Guarantees that the server never stores or learns the user's cloud password.
    /// Protects against dictionary attacks, eavesdropping, and man-in-the-middle.
    /// </summary>
    public static class Srp6aAuth
    {
        // RFC 5054 2048-bit prime (N)
        private static readonly BigInteger N = BigInteger.Parse(
            "00" + // positive sign
            "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
            "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
            "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
            "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
            "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87747" +
            "546738A4718473E0FBEA97AD9251E7604AC786406864C9126F83B193E5740C56" +
            "A88F814E6127D1F4B99F7D193107F025C378E4F65740EEA63FB1A77A5C0C0C7C" +
            "C8CA5B4A74F49C761310961256370E5C4FD45B914E3029E3ABEC6D511F60A5FB",
            System.Globalization.NumberStyles.HexNumber);

        private static readonly BigInteger g = 2; // Generator
        private static readonly BigInteger k;     // Multiplier k = H(N, g)

        static Srp6aAuth()
        {
            var nBytes = N.ToByteArray(isUnsigned: true, isBigEndian: true);
            var gBytes = g.ToByteArray(isUnsigned: true, isBigEndian: true);
            using var sha = SHA256.Create();
            var combined = new byte[nBytes.Length + gBytes.Length];
            Buffer.BlockCopy(nBytes, 0, combined, 0, nBytes.Length);
            Buffer.BlockCopy(gBytes, 0, combined, nBytes.Length, gBytes.Length);
            var hash = sha.ComputeHash(combined);
            k = new BigInteger(hash, isUnsigned: true, isBigEndian: true);
        }

        public static (string saltBase64, string verifierBase64) GenerateRegistrationVerifier(string password)
        {
            var salt = new byte[16];
            RandomNumberGenerator.Fill(salt);

            var x = ComputePrivateKey(password, salt);
            var v = BigInteger.ModPow(g, x, N);

            return (
                Convert.ToBase64String(salt),
                Convert.ToBase64String(v.ToByteArray(isUnsigned: true, isBigEndian: true))
            );
        }

        public static (string clientEphemeralPubBase64, string clientProofBase64) GenerateClientProof(
            string password,
            string saltBase64,
            string serverEphemeralPubBase64)
        {
            var salt = Convert.FromBase64String(saltBase64);
            var B = new BigInteger(Convert.FromBase64String(serverEphemeralPubBase64), isUnsigned: true, isBigEndian: true);

            if (B % N == 0) throw new CryptographicException("Invalid server ephemeral public key.");

            // Generate client ephemeral private key a
            var aBytes = new byte[32];
            RandomNumberGenerator.Fill(aBytes);
            var a = new BigInteger(aBytes, isUnsigned: true, isBigEndian: true);

            // Client ephemeral public key A = g^a mod N
            var A = BigInteger.ModPow(g, a, N);

            // Scrambling parameter u = H(A, B)
            var u = ComputeScramblingParameter(A, B);
            if (u == 0) throw new CryptographicException("Invalid scrambling parameter.");

            // Compute x
            var x = ComputePrivateKey(password, salt);

            // Compute shared secret S = (B - k * (g^x mod N)) ^ (a + u * x) mod N
            var gx = BigInteger.ModPow(g, x, N);
            var kgx = (k * gx) % N;
            var baseVal = (B - kgx + N) % N;
            var exp = a + (u * x);
            var S = BigInteger.ModPow(baseVal, exp, N);

            // Client proof M = H(A, B, S)
            var proof = ComputeProof(A, B, S);

            return (
                Convert.ToBase64String(A.ToByteArray(isUnsigned: true, isBigEndian: true)),
                Convert.ToBase64String(proof)
            );
        }

        public static (string serverEphemeralPubBase64, byte[] serverSecretB) GenerateServerChallenge(string verifierBase64)
        {
            var v = new BigInteger(Convert.FromBase64String(verifierBase64), isUnsigned: true, isBigEndian: true);

            // Server ephemeral private key b
            var bBytes = new byte[32];
            RandomNumberGenerator.Fill(bBytes);
            var b = new BigInteger(bBytes, isUnsigned: true, isBigEndian: true);

            // Server ephemeral public key B = (k * v + g^b) mod N
            var gb = BigInteger.ModPow(g, b, N);
            var kv = (k * v) % N;
            var B = (kv + gb) % N;

            return (
                Convert.ToBase64String(B.ToByteArray(isUnsigned: true, isBigEndian: true)),
                bBytes
            );
        }

        public static bool VerifyClientProof(
            string clientEphemeralPubBase64,
            string serverEphemeralPubBase64,
            byte[] serverSecretB,
            string verifierBase64,
            string clientProofBase64)
        {
            try
            {
                var A = new BigInteger(Convert.FromBase64String(clientEphemeralPubBase64), isUnsigned: true, isBigEndian: true);
                var B = new BigInteger(Convert.FromBase64String(serverEphemeralPubBase64), isUnsigned: true, isBigEndian: true);
                var b = new BigInteger(serverSecretB, isUnsigned: true, isBigEndian: true);
                var v = new BigInteger(Convert.FromBase64String(verifierBase64), isUnsigned: true, isBigEndian: true);

                if (A % N == 0) return false;

                // Scrambling parameter u = H(A, B)
                var u = ComputeScramblingParameter(A, B);
                if (u == 0) return false;

                // Compute shared secret S = (A * v^u) ^ b mod N
                var vu = BigInteger.ModPow(v, u, N);
                var Avu = (A * vu) % N;
                var S = BigInteger.ModPow(Avu, b, N);

                // Expected proof M = H(A, B, S)
                var expectedProof = ComputeProof(A, B, S);
                var actualProof = Convert.FromBase64String(clientProofBase64);

                return CryptographicOperations.FixedTimeEquals(expectedProof, actualProof);
            }
            catch
            {
                return false;
            }
        }

        private static BigInteger ComputePrivateKey(string password, byte[] salt)
        {
            var pwdBytes = Encoding.UTF8.GetBytes(password);
            var hash = Rfc2898DeriveBytes.Pbkdf2(pwdBytes, salt, 100_000, HashAlgorithmName.SHA256, 32);
            return new BigInteger(hash, isUnsigned: true, isBigEndian: true);
        }

        private static BigInteger ComputeScramblingParameter(BigInteger A, BigInteger B)
        {
            var aBytes = A.ToByteArray(isUnsigned: true, isBigEndian: true);
            var bBytes = B.ToByteArray(isUnsigned: true, isBigEndian: true);
            using var sha = SHA256.Create();
            var combined = new byte[aBytes.Length + bBytes.Length];
            Buffer.BlockCopy(aBytes, 0, combined, 0, aBytes.Length);
            Buffer.BlockCopy(bBytes, 0, combined, aBytes.Length, bBytes.Length);
            var hash = sha.ComputeHash(combined);
            return new BigInteger(hash, isUnsigned: true, isBigEndian: true);
        }

        private static byte[] ComputeProof(BigInteger A, BigInteger B, BigInteger S)
        {
            var aBytes = A.ToByteArray(isUnsigned: true, isBigEndian: true);
            var bBytes = B.ToByteArray(isUnsigned: true, isBigEndian: true);
            var sBytes = S.ToByteArray(isUnsigned: true, isBigEndian: true);

            using var sha = SHA256.Create();
            var combined = new byte[aBytes.Length + bBytes.Length + sBytes.Length];
            Buffer.BlockCopy(aBytes, 0, combined, 0, aBytes.Length);
            Buffer.BlockCopy(bBytes, 0, combined, aBytes.Length, bBytes.Length);
            Buffer.BlockCopy(sBytes, 0, combined, aBytes.Length + bBytes.Length, sBytes.Length);

            return sha.ComputeHash(combined);
        }
    }
}
