using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace Messa.Core.Crypto
{
    public class RatchetMessage
    {
        [JsonPropertyName("senderFp")]
        public string SenderFingerprint { get; set; } = string.Empty;

        [JsonPropertyName("recipientFp")]
        public string RecipientFingerprint { get; set; } = string.Empty;

        [JsonPropertyName("dhPub")]
        public string DhPublicKeyBase64 { get; set; } = string.Empty;

        [JsonPropertyName("msgNum")]
        public int MessageNumber { get; set; }

        [JsonPropertyName("prevChainLen")]
        public int PreviousChainLength { get; set; }

        [JsonPropertyName("iv")]
        public string IvBase64 { get; set; } = string.Empty;

        [JsonPropertyName("ciphertext")]
        public string CiphertextBase64 { get; set; } = string.Empty;

        [JsonPropertyName("tag")]
        public string TagBase64 { get; set; } = string.Empty;

        [JsonPropertyName("signature")]
        public string SignatureBase64 { get; set; } = string.Empty;

        [JsonPropertyName("timestamp")]
        public long Timestamp { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        public byte[] ComputeSignableBytes()
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms, Encoding.UTF8);
            bw.Write(SenderFingerprint);
            bw.Write(RecipientFingerprint);
            bw.Write(DhPublicKeyBase64);
            bw.Write(MessageNumber);
            bw.Write(PreviousChainLength);
            bw.Write(IvBase64);
            bw.Write(CiphertextBase64);
            bw.Write(TagBase64);
            bw.Write(Timestamp);
            return ms.ToArray();
        }
    }

    public class DoubleRatchetSession
    {
        private static readonly byte[] InfoRoot = Encoding.UTF8.GetBytes("MESSA_DOUBLE_RATCHET_ROOT");
        private static readonly byte[] StepChain = new byte[] { 0x01 };
        private static readonly byte[] StepMessage = new byte[] { 0x02 };

        public string PeerFingerprint { get; set; } = string.Empty;
        public string PeerSigningPublicKeyBase64 { get; set; } = string.Empty;

        // Session state
        private byte[] _rootKey = Array.Empty<byte>();
        private byte[]? _sendingChainKey;
        private byte[]? _receivingChainKey;
        private byte[] _localDhPrivateKey = Array.Empty<byte>();
        private byte[] _localDhPublicKey = Array.Empty<byte>();
        private byte[]? _remoteDhPublicKey;
        private int _ns = 0; // Number of sent messages in current chain
        private int _nr = 0; // Number of received messages in current chain
        private int _pn = 0; // Previous chain length

        /// <summary>
        /// Alice initiates session (Sender of first message)
        /// </summary>
        public static DoubleRatchetSession Initiate(IdentityKey myIdentity, PreKeyBundle peerBundle)
        {
            if (!peerBundle.Verify())
            {
                throw new CryptographicException("Peer PreKeyBundle signature verification failed! Possible MITM attack.");
            }

            // Perform X3DH-lite initial key agreement
            var peerSignedPreKeyBytes = Convert.FromBase64String(peerBundle.SignedPreKeyBase64);
            var peerIdentityDhBytes = Convert.FromBase64String(peerBundle.IdentityDhKeyBase64);

            using var peerPreKey = ECDiffieHellman.Create();
            peerPreKey.ImportSubjectPublicKeyInfo(peerSignedPreKeyBytes, out _);

            using var peerIdDh = ECDiffieHellman.Create();
            peerIdDh.ImportSubjectPublicKeyInfo(peerIdentityDhBytes, out _);

            // Local ephemeral DH key
            using var localEphem = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var localEphemPub = localEphem.ExportSubjectPublicKeyInfo();
            var localEphemPriv = localEphem.ExportPkcs8PrivateKey();

            // My Identity DH key
            using var myIdDh = ECDiffieHellman.Create();
            myIdDh.ImportPkcs8PrivateKey(Convert.FromBase64String(myIdentity.DhPrivateKeyBase64), out _);

            // DH1: Identity -> SignedPreKey
            var dh1 = myIdDh.DeriveKeyMaterial(peerPreKey.PublicKey);
            // DH2: Ephemeral -> Identity
            var dh2 = localEphem.DeriveKeyMaterial(peerIdDh.PublicKey);
            // DH3: Ephemeral -> SignedPreKey
            var dh3 = localEphem.DeriveKeyMaterial(peerPreKey.PublicKey);

            // Master Shared Key via HKDF
            var ikm = new byte[dh1.Length + dh2.Length + dh3.Length];
            Buffer.BlockCopy(dh1, 0, ikm, 0, dh1.Length);
            Buffer.BlockCopy(dh2, 0, ikm, dh1.Length, dh2.Length);
            Buffer.BlockCopy(dh3, 0, ikm, dh1.Length + dh2.Length, dh3.Length);

            var masterKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, null, Encoding.UTF8.GetBytes("MESSA_X3DH_MASTER"));

            // Initialize Double Ratchet with Bob's Signed Prekey as remote ratchet key
            var session = new DoubleRatchetSession
            {
                PeerFingerprint = peerBundle.Fingerprint,
                PeerSigningPublicKeyBase64 = peerBundle.IdentitySigningKeyBase64,
                _rootKey = masterKey,
                _localDhPrivateKey = localEphemPriv,
                _localDhPublicKey = localEphemPub,
                _remoteDhPublicKey = peerSignedPreKeyBytes
            };

            // Derive initial sending chain: DH(localEphem, peerPreKey)
            var dhSecret = localEphem.DeriveKeyMaterial(peerPreKey.PublicKey);
            var (nextRk, sendingCk) = KdfRoot(session._rootKey, dhSecret);
            session._rootKey = nextRk;
            session._sendingChainKey = sendingCk;

            return session;
        }

        /// <summary>
        /// Bob receives initial message and establishes session
        /// </summary>
        public static DoubleRatchetSession Accept(IdentityKey myIdentity, string senderFingerprint, string senderSigningPubKeyBase64, string senderIdentityDhPubKeyBase64, byte[] senderEphemeralDhPubKey)
        {
            using var senderIdDh = ECDiffieHellman.Create();
            senderIdDh.ImportSubjectPublicKeyInfo(Convert.FromBase64String(senderIdentityDhPubKeyBase64), out _);

            using var senderEphemDh = ECDiffieHellman.Create();
            senderEphemDh.ImportSubjectPublicKeyInfo(senderEphemeralDhPubKey, out _);

            using var myPreKey = ECDiffieHellman.Create();
            myPreKey.ImportPkcs8PrivateKey(Convert.FromBase64String(myIdentity.SignedPreKeyPrivateKeyBase64), out _);

            using var myIdDh = ECDiffieHellman.Create();
            myIdDh.ImportPkcs8PrivateKey(Convert.FromBase64String(myIdentity.DhPrivateKeyBase64), out _);

            // DH1: SenderIdentity -> MySignedPreKey
            var dh1 = myPreKey.DeriveKeyMaterial(senderIdDh.PublicKey);
            // DH2: SenderEphemeral -> MyIdentity
            var dh2 = myIdDh.DeriveKeyMaterial(senderEphemDh.PublicKey);
            // DH3: SenderEphemeral -> MySignedPreKey
            var dh3 = myPreKey.DeriveKeyMaterial(senderEphemDh.PublicKey);

            var ikm = new byte[dh1.Length + dh2.Length + dh3.Length];
            Buffer.BlockCopy(dh1, 0, ikm, 0, dh1.Length);
            Buffer.BlockCopy(dh2, 0, ikm, dh1.Length, dh2.Length);
            Buffer.BlockCopy(dh3, 0, ikm, dh1.Length + dh2.Length, dh3.Length);

            var masterKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, null, Encoding.UTF8.GetBytes("MESSA_X3DH_MASTER"));

            var session = new DoubleRatchetSession
            {
                PeerFingerprint = senderFingerprint,
                PeerSigningPublicKeyBase64 = senderSigningPubKeyBase64,
                _rootKey = masterKey,
                _localDhPrivateKey = myPreKey.ExportPkcs8PrivateKey(),
                _localDhPublicKey = myPreKey.ExportSubjectPublicKeyInfo(),
                _remoteDhPublicKey = senderEphemeralDhPubKey
            };

            // Derive initial receiving chain: DH(myPreKey, senderEphemeral)
            var dhSecret = myPreKey.DeriveKeyMaterial(senderEphemDh.PublicKey);
            var (nextRk, receivingCk) = KdfRoot(session._rootKey, dhSecret);
            session._rootKey = nextRk;
            session._receivingChainKey = receivingCk;

            return session;
        }

        public RatchetMessage Encrypt(string plaintext, IdentityKey myIdentity)
        {
            if (_sendingChainKey == null)
            {
                // Generate new local DH pair and ratchet forward
                using var newLocalDh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                _localDhPrivateKey = newLocalDh.ExportPkcs8PrivateKey();
                _localDhPublicKey = newLocalDh.ExportSubjectPublicKeyInfo();

                using var remoteDh = ECDiffieHellman.Create();
                remoteDh.ImportSubjectPublicKeyInfo(_remoteDhPublicKey!, out _);

                var dhSecret = newLocalDh.DeriveKeyMaterial(remoteDh.PublicKey);
                var (nextRk, sendingCk) = KdfRoot(_rootKey, dhSecret);
                _rootKey = nextRk;
                _sendingChainKey = sendingCk;
                _pn = _ns;
                _ns = 0;
            }

            // Advance sending chain
            var (nextChainKey, messageKey) = KdfChain(_sendingChainKey);
            _sendingChainKey = nextChainKey;

            var nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);

            var plainBytes = Encoding.UTF8.GetBytes(plaintext);
            var ciphertext = new byte[plainBytes.Length];
            var tag = new byte[16];

            using var aesGcm = new AesGcm(messageKey, 16);
            aesGcm.Encrypt(nonce, plainBytes, ciphertext, tag);

            // Wipe message key immediately (Forward Secrecy)
            CryptographicOperations.ZeroMemory(messageKey);

            var msg = new RatchetMessage
            {
                SenderFingerprint = myIdentity.Fingerprint,
                RecipientFingerprint = PeerFingerprint,
                DhPublicKeyBase64 = Convert.ToBase64String(_localDhPublicKey),
                MessageNumber = _ns++,
                PreviousChainLength = _pn,
                IvBase64 = Convert.ToBase64String(nonce),
                CiphertextBase64 = Convert.ToBase64String(ciphertext),
                TagBase64 = Convert.ToBase64String(tag),
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            // Sign the message envelope with Alice's Identity Signing Key
            var signable = msg.ComputeSignableBytes();
            var signature = myIdentity.Sign(signable);
            msg.SignatureBase64 = Convert.ToBase64String(signature);

            return msg;
        }

        public string Decrypt(RatchetMessage message)
        {
            // 1. Cryptographic Authentication: Verify Digital Signature
            var signable = message.ComputeSignableBytes();
            var sigBytes = Convert.FromBase64String(message.SignatureBase64);
            if (!IdentityKey.VerifySignature(signable, sigBytes, PeerSigningPublicKeyBase64))
            {
                throw new CryptographicException("DIGITAL SIGNATURE FAILED! Message was tampered with or sender was spoofed!");
            }

            var incomingDhPubBytes = Convert.FromBase64String(message.DhPublicKeyBase64);

            // 2. Check if DH ratchet step is needed (remote sent a new DH key)
            if (_remoteDhPublicKey == null || !CryptographicOperations.FixedTimeEquals(_remoteDhPublicKey, incomingDhPubBytes))
            {
                // Advance DH Ratchet
                _pn = _ns;
                _ns = 0;
                _nr = 0;
                _remoteDhPublicKey = incomingDhPubBytes;

                // Step 1: DH with local DH private key + incoming DH public key
                using var localDh = ECDiffieHellman.Create();
                localDh.ImportPkcs8PrivateKey(_localDhPrivateKey, out _);

                using var remoteDh = ECDiffieHellman.Create();
                remoteDh.ImportSubjectPublicKeyInfo(_remoteDhPublicKey, out _);

                var dhSecret1 = localDh.DeriveKeyMaterial(remoteDh.PublicKey);
                var (rk1, recvCk) = KdfRoot(_rootKey, dhSecret1);
                _rootKey = rk1;
                _receivingChainKey = recvCk;

                // Step 2: Generate new local DH pair for future responses
                using var newLocalDh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                _localDhPrivateKey = newLocalDh.ExportPkcs8PrivateKey();
                _localDhPublicKey = newLocalDh.ExportSubjectPublicKeyInfo();

                var dhSecret2 = newLocalDh.DeriveKeyMaterial(remoteDh.PublicKey);
                var (rk2, sendCk) = KdfRoot(_rootKey, dhSecret2);
                _rootKey = rk2;
                _sendingChainKey = sendCk;
            }

            if (_receivingChainKey == null)
            {
                throw new CryptographicException("Receiving chain key is not initialized.");
            }

            // 3. Fast-forward symmetric ratchet to message number
            while (_nr < message.MessageNumber)
            {
                var (nextCk, skippedKey) = KdfChain(_receivingChainKey);
                _receivingChainKey = nextCk;
                CryptographicOperations.ZeroMemory(skippedKey);
                _nr++;
            }

            var (finalNextCk, currentMessageKey) = KdfChain(_receivingChainKey);
            _receivingChainKey = finalNextCk;
            _nr++;

            // 4. Decrypt via AES-256-GCM
            var nonce = Convert.FromBase64String(message.IvBase64);
            var ciphertext = Convert.FromBase64String(message.CiphertextBase64);
            var tag = Convert.FromBase64String(message.TagBase64);
            var plaintextBytes = new byte[ciphertext.Length];

            using var aesGcm = new AesGcm(currentMessageKey, 16);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintextBytes);

            // Wipe message key immediately
            CryptographicOperations.ZeroMemory(currentMessageKey);

            return Encoding.UTF8.GetString(plaintextBytes);
        }

        private static (byte[] nextRootKey, byte[] chainKey) KdfRoot(byte[] rootKey, byte[] dhSecret)
        {
            var output = HKDF.DeriveKey(HashAlgorithmName.SHA256, dhSecret, 64, rootKey, InfoRoot);
            var nextRk = new byte[32];
            var chainKey = new byte[32];
            Buffer.BlockCopy(output, 0, nextRk, 0, 32);
            Buffer.BlockCopy(output, 32, chainKey, 0, 32);
            return (nextRk, chainKey);
        }

        private static (byte[] nextChainKey, byte[] messageKey) KdfChain(byte[] chainKey)
        {
            using var hmac = new HMACSHA256(chainKey);
            var nextChainKey = hmac.ComputeHash(StepChain);
            var messageKey = hmac.ComputeHash(StepMessage);
            return (nextChainKey, messageKey);
        }
    }
}
