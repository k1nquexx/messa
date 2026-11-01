// ==============================================================================
// WebCrypto E2EE Модуль для Браузера и ПК (crypto-web.js)
// Алгоритмы:
// - Ключи идентификации: Curve25519 (X25519) с автоматическим переходом на P-256 (ECDH)
// - Выработка секрета: ECDH + AES-GCM (256-бит)
// - Forward Secrecy: новый одноразовый ключ на каждое сообщение
// - Высокоскоростное блочное кодирование для фото и голосовых сообщений
// ==============================================================================

class WebCryptoE2EE {
    static get subtle() {
        return window.crypto.subtle;
    }

    /**
     * Быстрое чанковое преобразование ArrayBuffer в Base64 (для фото и аудио)
     */
    static buf2b64(buffer) {
        const bytes = new Uint8Array(buffer);
        const chunkSize = 0x8000; // 32KB чанки исключают переполнение стека
        let binary = '';
        for (let i = 0; i < bytes.length; i += chunkSize) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
        }
        return window.btoa(binary);
    }

    /**
     * Быстрое преобразование Base64 в ArrayBuffer
     */
    static b642buf(base64) {
        const binary = window.atob(base64);
        const len = binary.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    static buf2hex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Всегда используем международный стандарт NIST P-256 (ECDH) для 100% совместимости:
     * Браузер <-> Android Capacitor <-> Нативный Windows C# (WPF)
     */
    static async isX25519Supported() {
        return false; // Принудительно P-256 для сквозной совместимости с Windows C#
    }

    /**
     * Генерация криптопары устройства (X25519 или совместимый P-256)
     */
    static async generateIdentity() {
        const hasX25519 = await this.isX25519Supported();
        const algo = hasX25519 ? { name: 'X25519' } : { name: 'ECDH', namedCurve: 'P-256' };

        const keyPair = await this.subtle.generateKey(
            algo,
            true,
            ['deriveKey', 'deriveBits']
        );

        const rawPub = await this.subtle.exportKey('raw', keyPair.publicKey);
        const pkcs8Priv = await this.subtle.exportKey('pkcs8', keyPair.privateKey);

        const hashBuf = await this.subtle.digest('SHA-256', rawPub);
        const id = this.buf2hex(hashBuf);

        const publicKeyB64 = this.buf2b64(rawPub);
        const privateKeyB64 = this.buf2b64(pkcs8Priv);

        return {
            id,
            algo: hasX25519 ? 'X25519' : 'P-256',
            publicKeyB64,
            privateKeyB64
        };
    }

    /**
     * Зашифровать сообщение/файл/аудио для получателя
     */
    static async encryptMessage(recipientPublicKeyB64, payload) {
        const recipientPubBuf = this.b642buf(recipientPublicKeyB64);
        const isX25519 = recipientPubBuf.byteLength === 32;
        const algo = isX25519 ? { name: 'X25519' } : { name: 'ECDH', namedCurve: 'P-256' };

        // 1. Одноразовый эфемерный ключ (Forward Secrecy)
        const ephKeyPair = await this.subtle.generateKey(algo, true, ['deriveKey', 'deriveBits']);
        const ephPubRaw = await this.subtle.exportKey('raw', ephKeyPair.publicKey);
        const ephPubB64 = this.buf2b64(ephPubRaw);

        // 2. Импорт открытого ключа получателя
        const recipientPub = await this.subtle.importKey('raw', recipientPubBuf, algo, false, []);

        // 3. Выработка общего ключа AES-GCM через SHA-256 (совместимость с C# CNG KeyDerivationFunction.Hash)
        const deriveAlgo = isX25519 ? { name: 'X25519', public: recipientPub } : { name: 'ECDH', public: recipientPub };
        const rawSecretBits = await this.subtle.deriveBits(deriveAlgo, ephKeyPair.privateKey, 256);
        const hashedKeyBytes = await this.subtle.digest('SHA-256', rawSecretBits);
        const sharedKey = await this.subtle.importKey('raw', hashedKeyBytes, { name: 'AES-GCM' }, false, ['encrypt']);

        // 4. Шифрование данных
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const plaintext = new TextEncoder().encode(JSON.stringify(payload));
        const ciphertextBuf = await this.subtle.encrypt(
            { name: 'AES-GCM', iv },
            sharedKey,
            plaintext
        );

        return {
            ephemeralPub: ephPubB64,
            iv: this.buf2b64(iv),
            ciphertext: this.buf2b64(ciphertextBuf)
        };
    }

    /**
     * Расшифровать входящий пакет
     */
    static async decryptMessage(myPrivateKeyB64, envelope) {
        const { ephemeralPub, iv, ciphertext } = envelope;

        const ephPubBuf = this.b642buf(ephemeralPub);
        const isX25519 = ephPubBuf.byteLength === 32;
        const algo = isX25519 ? { name: 'X25519' } : { name: 'ECDH', namedCurve: 'P-256' };

        // 1. Восстановление приватного ключа
        const myPrivKey = await this.subtle.importKey('pkcs8', this.b642buf(myPrivateKeyB64), algo, false, ['deriveKey', 'deriveBits']);

        // 2. Восстановление эфемерного публичного ключа
        const ephPubKey = await this.subtle.importKey('raw', ephPubBuf, algo, false, []);

        // 3. Выработка общего AES-GCM ключа через SHA-256 (совместимость с C# CNG)
        const deriveAlgo = isX25519 ? { name: 'X25519', public: ephPubKey } : { name: 'ECDH', public: ephPubKey };
        const rawSecretBits = await this.subtle.deriveBits(deriveAlgo, myPrivKey, 256);
        const hashedKeyBytes = await this.subtle.digest('SHA-256', rawSecretBits);
        const sharedKey = await this.subtle.importKey('raw', hashedKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']);

        // 4. Расшифровка
        const plaintextBuf = await this.subtle.decrypt(
            { name: 'AES-GCM', iv: this.b642buf(iv) },
            sharedKey,
            this.b642buf(ciphertext)
        );

        const decodedStr = new TextDecoder().decode(plaintextBuf);
        return JSON.parse(decodedStr);
    }
}
