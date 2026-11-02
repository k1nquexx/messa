using System;
using System.Security.Cryptography;
using Messa.Core.Crypto;
using Xunit;

namespace Messa.Tests
{
    public class DoubleRatchetTests
    {
        [Fact]
        public void DigitalSignature_ShouldDetectSpoofingAndTampering()
        {
            var alice = IdentityKey.Generate("alice");
            var bob = IdentityKey.Generate("bob");
            var eve = IdentityKey.Generate("eve");

            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var signature = alice.Sign(data);

            // 1. Bob verifies Alice's valid signature -> True
            Assert.True(IdentityKey.VerifySignature(data, signature, alice.SigningPublicKeyBase64));

            // 2. Tampered data -> False
            var tamperedData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 99 };
            Assert.False(IdentityKey.VerifySignature(tamperedData, signature, alice.SigningPublicKeyBase64));

            // 3. Eve tries to claim Alice's signature with Eve's key -> False
            Assert.False(IdentityKey.VerifySignature(data, signature, eve.SigningPublicKeyBase64));
        }

        [Fact]
        public void PreKeyBundle_Verification_ShouldSucceedForValidSignature()
        {
            var bob = IdentityKey.Generate("bob");
            var bundle = PreKeyBundle.Create(bob);

            Assert.True(bundle.Verify());

            // Tamper bundle
            var tamperedBytes = Convert.FromBase64String(bundle.SignedPreKeyBase64);
            tamperedBytes[0] ^= 0xFF;
            bundle.SignedPreKeyBase64 = Convert.ToBase64String(tamperedBytes);

            Assert.False(bundle.Verify());
        }

        [Fact]
        public void DoubleRatchet_FullSession_ShouldEncryptAndDecryptMultiTurn()
        {
            var alice = IdentityKey.Generate("alice");
            var bob = IdentityKey.Generate("bob");
            var bobBundle = PreKeyBundle.Create(bob);

            // Alice initiates session
            var aliceSession = DoubleRatchetSession.Initiate(alice, bobBundle);

            // 1. Alice sends first message
            var msg1 = aliceSession.Encrypt("Hello Bob, this is sovereign Alice!", alice);
            Assert.NotNull(msg1);
            Assert.False(string.IsNullOrEmpty(msg1.SignatureBase64));

            // Bob accepts session on first message
            var bobSession = DoubleRatchetSession.Accept(
                bob,
                alice.Fingerprint,
                alice.SigningPublicKeyBase64,
                alice.DhPublicKeyBase64,
                Convert.FromBase64String(msg1.DhPublicKeyBase64));

            var decrypted1 = bobSession.Decrypt(msg1);
            Assert.Equal("Hello Bob, this is sovereign Alice!", decrypted1);

            // 2. Bob replies (DH Ratchet step occurs)
            var msg2 = bobSession.Encrypt("Hi Alice! Message decrypted with Forward Secrecy.", bob);
            var decrypted2 = aliceSession.Decrypt(msg2);
            Assert.Equal("Hi Alice! Message decrypted with Forward Secrecy.", decrypted2);

            // 3. Alice sends second message
            var msg3 = aliceSession.Encrypt("Does the DH ratchet advance on each round?", alice);
            var decrypted3 = bobSession.Decrypt(msg3);
            Assert.Equal("Does the DH ratchet advance on each round?", decrypted3);

            // 4. Bob sends multiple messages in sequence (Symmetric Ratchet chain)
            var msg4_1 = bobSession.Encrypt("Yes, absolutely!", bob);
            var msg4_2 = bobSession.Encrypt("And each message key is wiped from memory.", bob);

            var decrypted4_1 = aliceSession.Decrypt(msg4_1);
            var decrypted4_2 = aliceSession.Decrypt(msg4_2);

            Assert.Equal("Yes, absolutely!", decrypted4_1);
            Assert.Equal("And each message key is wiped from memory.", decrypted4_2);
        }

        [Fact]
        public void DoubleRatchet_SpoofedSender_ShouldFailCryptographicVerification()
        {
            var alice = IdentityKey.Generate("alice");
            var bob = IdentityKey.Generate("bob");
            var eve = IdentityKey.Generate("eve");
            var bobBundle = PreKeyBundle.Create(bob);

            var aliceSession = DoubleRatchetSession.Initiate(alice, bobBundle);
            var msg = aliceSession.Encrypt("Legitimate message", alice);

            // Eve intercepts and tries to sign with her own key claiming to be Alice
            var eveSignable = msg.ComputeSignableBytes();
            msg.SignatureBase64 = Convert.ToBase64String(eve.Sign(eveSignable));

            var bobSession = DoubleRatchetSession.Accept(
                bob,
                alice.Fingerprint,
                alice.SigningPublicKeyBase64,
                alice.DhPublicKeyBase64,
                Convert.FromBase64String(msg.DhPublicKeyBase64));

            // Bob must reject because signature doesn't match Alice's identity public key!
            Assert.Throws<CryptographicException>(() => bobSession.Decrypt(msg));
        }
    }
}
