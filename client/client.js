// ==============================================================================
// КЛИЕНТ МЕССЕНДЖЕРА (Сетевой транспорт + E2EE)
// ==============================================================================

const SovereignCrypto = require('./crypto');
const WebSocket = typeof globalThis.WebSocket !== 'undefined' ? globalThis.WebSocket : require('../server/node_modules/ws');

class SovereignClient {
    constructor(name) {
        this.name = name;
        this.identity = SovereignCrypto.generateIdentity();
        this.ws = null;
        this.onMessageCallback = null;
    }

    /**
     * Подключение к слепому релей-серверу
     */
    connect(serverUrl) {
        return new Promise((resolve, reject) => {
            this.ws = new WebSocket(serverUrl);

            this.ws.onopen = () => {
                console.log(`[${this.name}] Подключен к серверу по WebSocket`);
                // Сразу регистрируемся в сети под своим публичным ID
                this.ws.send(JSON.stringify({
                    action: 'register',
                    clientId: this.identity.id
                }));
            };

            this.ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    
                    if (data.action === 'registered') {
                        console.log(`[${this.name}] Успешно зарегистрирован в сети. ID: ${this.identity.id.slice(0, 16)}...`);
                        resolve();
                    } else if (data.action === 'incoming_envelope') {
                        // Получен зашифрованный конверт
                        this._handleIncomingEnvelope(data);
                    }
                } catch (err) {
                    console.error(`[${this.name}] Ошибка разбора сообщения:`, err.message);
                }
            };

            this.ws.onerror = (err) => {
                console.error(`[${this.name}] Ошибка сети:`, err);
                reject(err);
            };
        });
    }

    /**
     * Отправка зашифрованного E2EE-сообщения собеседнику
     */
    sendEncryptedMessage(recipientId, recipientPublicKeyB64, text) {
        const payload = {
            text: text,
            senderId: this.identity.id,
            senderPublicKeyB64: this.identity.publicKeyB64,
            timestamp: Date.now()
        };

        // 1. Полное сквозное шифрование на клиенте
        const envelope = SovereignCrypto.encryptEnvelope(recipientPublicKeyB64, payload);

        // 2. Отправка слепого конверта через релей
        this.ws.send(JSON.stringify({
            action: 'send_envelope',
            to: recipientId,
            envelope: envelope
        }));

        console.log(`[${this.name}] Отправил зашифрованное сообщение для ${recipientId.slice(0, 16)}...`);
    }

    /**
     * Обработка и расшифровка входящего конверта
     */
    _handleIncomingEnvelope(data) {
        try {
            const envelope = data.envelope;
            // Расшифровываем своим приватным ключом
            const decrypted = SovereignCrypto.decryptEnvelope(this.identity.privateKeyB64, envelope);
            
            if (this.onMessageCallback) {
                this.onMessageCallback(decrypted, envelope);
            }
        } catch (err) {
            console.error(`[${this.name}] Ошибка дешифрования (возможно, пакет поврежден или чужой):`, err.message);
        }
    }

    onMessage(callback) {
        this.onMessageCallback = callback;
    }

    close() {
        if (this.ws) {
            this.ws.close();
        }
    }
}

module.exports = SovereignClient;
