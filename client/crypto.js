// ==============================================================================
// КЛИЕНТСКИЙ КРИПТОГРАФИЧЕСКИЙ МОДУЛЬ (E2EE) - ЕДИНЫЙ СТАНДАРТ ДЛЯ ВСЕХ ПЛАТФОРМ
// Алгоритмы:
// - Ключи: NIST P-256 (prime256v1 / secp256r1, 65 байт ANSI X9.62 с префиксом 0x04)
// - Выработка общего секрета: ECDH (P-256) -> 32 байта общего секрета
// - Симметричный шифр: AES-256-GCM (12 байт IV, 16 байт тег целостности)
// - Формат пакета: { ephemeralPub: Base64, iv: Base64, ciphertext: Base64(шифр + тег) }
// 100% совместимо с WebCrypto (crypto-web.js), Android (Capacitor) и C# Windows (CIPHER.exe)
// ==============================================================================

const crypto = require('node:crypto');

class SovereignCrypto {
    /**
     * Создание новой суверенной криптографической личности (Identity) прямо на устройстве.
     */
    static generateIdentity() {
        const ecdh = crypto.createECDH('prime256v1');
        ecdh.generateKeys();

        const pubBytes = ecdh.getPublicKey(); // 65 байт: 0x04 || X || Y
        const privBytes = ecdh.getPrivateKey(); // 32 байта

        const id = crypto.createHash('sha256').update(pubBytes).digest('hex');

        return {
            id,
            publicKeyB64: pubBytes.toString('base64'),
            privateKeyB64: privBytes.toString('base64')
        };
    }

    /**
     * Зашифровать сообщение для получателя.
     * @param {string} recipientPublicKeyB64 - Открытый ключ собеседника (65 байт в Base64)
     * @param {object} payload - Данные (текст, вложения, время)
     * @returns {object} Зашифрованный конверт (Envelope)
     */
    static encryptEnvelope(recipientPublicKeyB64, payload) {
        // 1. Одноразовый эфемерный ключ P-256 (Forward Secrecy)
        const ephEcdh = crypto.createECDH('prime256v1');
        ephEcdh.generateKeys();
        const ephPub = ephEcdh.getPublicKey();

        // 2. Вычисление общего секрета с открытым ключом получателя и хеширование SHA-256 (совместимость с C# CNG KeyDerivationFunction.Hash)
        const recipientPubBuf = Buffer.from(recipientPublicKeyB64, 'base64');
        const rawSecret = ephEcdh.computeSecret(recipientPubBuf);
        const sharedSecret = crypto.createHash('sha256').update(rawSecret).digest();

        // 3. Генерация 12-байтного IV для AES-GCM
        const iv = crypto.randomBytes(12);

        // 4. Шифрование данных через AES-256-GCM
        const cipher = crypto.createCipheriv('aes-256-gcm', sharedSecret, iv);
        const jsonText = JSON.stringify(payload);
        
        const encrypted = Buffer.concat([cipher.update(jsonText, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag(); // 16 байт

        // WebCrypto / C# формат: ciphertext || authTag (слитно)
        const combinedCiphertext = Buffer.concat([encrypted, authTag]);

        return {
            ephemeralPub: ephPub.toString('base64'),
            iv: iv.toString('base64'),
            ciphertext: combinedCiphertext.toString('base64')
        };
    }

    /**
     * Расшифровать входящий конверт.
     * @param {string} myPrivateKeyB64 - Закрытый ключ получателя (32 байта в Base64)
     * @param {object} envelope - Зашифрованный конверт
     * @returns {object} Исходное сообщение
     */
    static decryptEnvelope(myPrivateKeyB64, envelope) {
        const { ephemeralPub, iv, ciphertext } = envelope;

        const ephPubBuf = Buffer.from(ephemeralPub, 'base64');
        const privBuf = Buffer.from(myPrivateKeyB64, 'base64');

        const myEcdh = crypto.createECDH('prime256v1');
        myEcdh.setPrivateKey(privBuf);

        // Вычисляем 32-байтный общий секрет и хешируем через SHA-256 (совместимость с C# CNG)
        const rawSecret = myEcdh.computeSecret(ephPubBuf);
        const sharedSecret = crypto.createHash('sha256').update(rawSecret).digest();

        // Разделяем шифротекст и 16-байтный тег
        const combined = Buffer.from(ciphertext, 'base64');
        const cipherLen = combined.length - 16;
        const cipherBytes = combined.subarray(0, cipherLen);
        const authTag = combined.subarray(cipherLen);

        const ivBuf = Buffer.from(iv, 'base64');

        const decipher = crypto.createDecipheriv('aes-256-gcm', sharedSecret, ivBuf);
        decipher.setAuthTag(authTag);

        const decrypted = Buffer.concat([decipher.update(cipherBytes), decipher.final()]);
        return JSON.parse(decrypted.toString('utf8'));
    }
}

module.exports = SovereignCrypto;
