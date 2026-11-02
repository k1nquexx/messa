using System;
using System.Security.Cryptography;
using System.Text;
using Messa.Core.Crypto;
using Messa.Core.Models;
using Xunit;

namespace Messa.Tests
{
    public class AuthAndProfileTests
    {
        [Fact]
        public void ChallengeResponse_AuthenticatesLegitimateOwner()
        {
            var alice = IdentityKey.Generate("alice");

            // Server generates 32-byte nonce
            var nonceBytes = new byte[32];
            RandomNumberGenerator.Fill(nonceBytes);
            var nonceBase64 = Convert.ToBase64String(nonceBytes);

            // Alice signs the nonce
            var signature = alice.Sign(nonceBytes);
            var sigBase64 = Convert.ToBase64String(signature);

            // Server verifies:
            // 1. Verify that SHA-256(SigningPublicKey) == Fingerprint
            var pubBytes = Convert.FromBase64String(alice.SigningPublicKeyBase64);
            using var sha = SHA256.Create();
            var computedFp = Convert.ToHexString(sha.ComputeHash(pubBytes)).ToLowerInvariant();
            Assert.Equal(alice.Fingerprint, computedFp);

            // 2. Verify ECDSA signature of nonce
            var isValid = IdentityKey.VerifySignature(nonceBytes, signature, alice.SigningPublicKeyBase64);
            Assert.True(isValid);
        }

        [Fact]
        public void ChallengeResponse_RejectsSpoofedSignature()
        {
            var alice = IdentityKey.Generate("alice");
            var eve = IdentityKey.Generate("eve");

            var nonceBytes = new byte[32];
            RandomNumberGenerator.Fill(nonceBytes);

            // Eve signs with HER key but claims Alice's public key / fingerprint
            var eveSig = eve.Sign(nonceBytes);

            var isValid = IdentityKey.VerifySignature(nonceBytes, eveSig, alice.SigningPublicKeyBase64);
            Assert.False(isValid);
        }

        [Fact]
        public void Srp6a_2FA_ZeroKnowledgeProof_VerifiesCorrectPassword()
        {
            var password = "SuperSecretMasterCloudPassword#2026!";

            // 1. User registers 2FA cloud password
            var (salt, verifier) = Srp6aAuth.GenerateRegistrationVerifier(password);
            Assert.False(string.IsNullOrEmpty(salt));
            Assert.False(string.IsNullOrEmpty(verifier));

            // 2. Server generates authentication challenge
            var (serverB, secretB) = Srp6aAuth.GenerateServerChallenge(verifier);

            // 3. Client generates proof using password
            var (clientA, clientProof) = Srp6aAuth.GenerateClientProof(password, salt, serverB);

            // 4. Server verifies client proof WITHOUT knowing password
            var isSuccess = Srp6aAuth.VerifyClientProof(clientA, serverB, secretB, verifier, clientProof);
            Assert.True(isSuccess);
        }

        [Fact]
        public void Srp6a_2FA_RejectsWrongPassword()
        {
            var correctPassword = "CorrectPassword123";
            var wrongPassword = "WrongPassword456";

            var (salt, verifier) = Srp6aAuth.GenerateRegistrationVerifier(correctPassword);
            var (serverB, secretB) = Srp6aAuth.GenerateServerChallenge(verifier);

            // Attacker guesses wrong password
            var (clientA, wrongProof) = Srp6aAuth.GenerateClientProof(wrongPassword, salt, serverB);

            var isSuccess = Srp6aAuth.VerifyClientProof(clientA, serverB, secretB, verifier, wrongProof);
            Assert.False(isSuccess);
        }

        [Fact]
        public void ContactCard_InviteLink_RoundTrip()
        {
            var contact = new ContactCard
            {
                Username = "alice",
                DisplayName = "Alice Sovereign",
                Fingerprint = "a1b2c3d4e5f600112233445566778899aabbccddeeff00112233445566778899"
            };

            var link = contact.ToInviteLink();
            Assert.StartsWith("messa://contact?", link);

            var parsed = ContactCard.FromInviteLink(link);
            Assert.NotNull(parsed);
            Assert.Equal(contact.Username, parsed.Username);
            Assert.Equal(contact.DisplayName, parsed.DisplayName);
            Assert.Equal(contact.Fingerprint, parsed.Fingerprint);
        }
    }
}
