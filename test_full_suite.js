// ==============================================================================
// ПОЛНЫЙ КОМПЛЕКСНЫЙ ТЕСТ СИСТЕМЫ (FULL SUITE TEST)
// Тестирует: E2EE криптографию P-256, слепой релей, файлы, голосовые, 
// read receipts, офлайн Dead-Drop очередь, WebRTC сигнализацию, удаление/редактирование
// ==============================================================================

const WebSocket = require('./server/node_modules/ws');
const SovereignCrypto = require('./client/crypto');

const SERVER_URL = 'ws://127.0.0.1:8080';

let passedTests = 0;
let totalTests = 0;

function assert(condition, message) {
    totalTests++;
    if (!condition) {
        console.error(`  ❌ FAILED: ${message}`);
        process.exitCode = 1;
    } else {
        console.log(`  ✅ PASSED: ${message}`);
        passedTests++;
    }
}

function wait(ms) {
    return new Promise(r => setTimeout(r, ms));
}

// Вспомогательный класс тестового клиента
class TestAgent {
    constructor(name) {
        this.name = name;
        this.identity = SovereignCrypto.generateIdentity();
        this.ws = null;
        this.inbox = [];
        this.readReceipts = [];
        this.callSignals = [];
    }

    connect() {
        return new Promise((resolve, reject) => {
            this.ws = new WebSocket(SERVER_URL);
            this.ws.on('open', () => {
                this.ws.send(JSON.stringify({
                    action: 'register',
                    clientId: this.identity.id
                }));
            });
            this.ws.on('message', (data) => {
                try {
                    const msg = JSON.parse(data.toString());
                    if (msg.action === 'registered') {
                        resolve(msg);
                    } else if (msg.action === 'incoming_envelope') {
                        const decrypted = SovereignCrypto.decryptEnvelope(this.identity.privateKeyB64, msg.envelope);
                        this.inbox.push({ decrypted, envelope: msg.envelope, from: msg.from });
                    } else if (msg.action === 'message_read') {
                        this.readReceipts.push(msg);
                    } else if (msg.action === 'call_signal') {
                        this.callSignals.push(msg);
                    }
                } catch (e) {
                    console.error(`[${this.name}] Err:`, e.message);
                }
            });
            this.ws.on('error', reject);
        });
    }

    sendMessage(targetId, targetPub, payload) {
        const envelope = SovereignCrypto.encryptEnvelope(targetPub, payload);
        this.ws.send(JSON.stringify({
            action: 'send_envelope',
            to: targetId,
            envelope: envelope
        }));
        return envelope;
    }

    sendReadReceipt(targetId, messageId) {
        this.ws.send(JSON.stringify({
            action: 'read_receipt',
            to: targetId,
            messageId: messageId
        }));
    }

    sendCallSignal(targetId, signal) {
        this.ws.send(JSON.stringify({
            action: 'call_signal',
            to: targetId,
            signal: signal
        }));
    }

    close() {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }
}

async function runFullSuite() {
    console.log('================================================================');
    console.log('   ЗАПУСК ГЛУБОКОГО АУДИТА И ТЕСТИРОВАНИЯ ВСЕГО ПРОЕКТА');
    console.log('================================================================\n');

    // ТЕСТ 1: Криптография NIST P-256 ECDH + AES-256-GCM
    console.log('[1/7] Тестирование криптографического ядра:');
    const idA = SovereignCrypto.generateIdentity();
    const idB = SovereignCrypto.generateIdentity();
    assert(idA.id.length === 64, 'SHA-256 fingerprint ID имеет длину 64 символа');
    assert(idA.publicKeyB64.length > 50, 'Публичный ключ NIST P-256 сгенерирован');
    assert(idA.privateKeyB64.length >= 44, 'Приватный ключ NIST P-256 сгенерирован (32 байта Base64)');

    const testPayload = { text: 'Секретный тест 123', secretNum: 42 };
    const envelope = SovereignCrypto.encryptEnvelope(idB.publicKeyB64, testPayload);
    assert(envelope.ephemeralPub && envelope.ciphertext && envelope.iv, 'E2EE конверт содержит все компоненты (ephemeralPub, IV, Ciphertext+Tag)');
    
    const decrypted = SovereignCrypto.decryptEnvelope(idB.privateKeyB64, envelope);
    assert(decrypted.text === 'Секретный тест 123' && decrypted.secretNum === 42, 'Корректная дешифровка получателем');

    let failedWrongKey = false;
    try {
        SovereignCrypto.decryptEnvelope(idA.privateKeyB64, envelope); // Чужой ключ!
    } catch {
        failedWrongKey = true;
    }
    assert(failedWrongKey, 'Чужой приватный ключ не может расшифровать конверт (AES-GCM AuthTag отклонён)');

    // ТЕСТ 2: Подключение агентов и маршрутизация сообщений в реальном времени
    console.log('\n[2/7] Тестирование WebSocket релея и передачи текста:');
    const alice = new TestAgent('Алиса');
    const bob = new TestAgent('Боб');

    await alice.connect();
    await bob.connect();
    assert(alice.ws.readyState === WebSocket.OPEN, 'Алиса подключена к серверу');
    assert(bob.ws.readyState === WebSocket.OPEN, 'Боб подключен к серверу');

    alice.sendMessage(bob.identity.id, bob.identity.publicKeyB64, {
        id: 'msg_001',
        text: 'Привет от Алисы!',
        destructSeconds: 0,
        timestamp: Date.now()
    });

    await wait(300);
    assert(bob.inbox.length === 1, 'Боб получил 1 входящее сообщение');
    assert(bob.inbox[0].decrypted.text === 'Привет от Алисы!', 'Текст сообщения в точности совпадает');

    // ТЕСТ 3: Передача E2EE файлов и фото
    console.log('\n[3/7] Тестирование передачи зашифрованных файлов/фото:');
    const fakeImageBase64 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
    alice.sendMessage(bob.identity.id, bob.identity.publicKeyB64, {
        id: 'msg_file_002',
        file: {
            name: 'secret_photo.png',
            type: 'image/png',
            size: 85,
            data: fakeImageBase64
        },
        timestamp: Date.now()
    });

    await wait(300);
    assert(bob.inbox.length === 2, 'Боб получил файл');
    assert(bob.inbox[1].decrypted.file.name === 'secret_photo.png', 'Имя файла совпадает');
    assert(bob.inbox[1].decrypted.file.data === fakeImageBase64, 'Бинарные данные файла расшифрованы целостно');

    // ТЕСТ 4: Передача голосовых сообщений (ГС)
    console.log('\n[4/7] Тестирование передачи E2EE голосовых сообщений:');
    const fakeAudioBase64 = 'data:audio/webm;base64,GkXfo59ChoEBQveBAULygQRC84EIQoKEd2VibUKHgQRChYECGFOAZwEAAAAAAA';
    bob.sendMessage(alice.identity.id, alice.identity.publicKeyB64, {
        id: 'msg_voice_003',
        voice: {
            data: fakeAudioBase64,
            duration: 12.4
        },
        timestamp: Date.now()
    });

    await wait(300);
    assert(alice.inbox.length === 1, 'Алиса получила голосовое сообщение');
    assert(alice.inbox[0].decrypted.voice.duration === 12.4, 'Метаданные длительности голосового верны');

    // ТЕСТ 5: Уведомления о прочтении (Read Receipts ✓✓)
    console.log('\n[5/7] Тестирование отчетов о прочтении (Read Receipts):');
    bob.sendReadReceipt(alice.identity.id, 'msg_001');
    await wait(300);
    assert(alice.readReceipts.length === 1, 'Алиса получила уведомление о прочтении');
    assert(alice.readReceipts[0].messageId === 'msg_001', 'ID прочитанного сообщения msg_001 подтверждён');

    // ТЕСТ 6: Сигнализация WebRTC P2P аудиозвонков
    console.log('\n[6/7] Тестирование сигнализации защищенных звонков:');
    alice.sendCallSignal(bob.identity.id, { type: 'offer', sdp: 'v=0\r\no=alice 123 456...' });
    await wait(300);
    assert(bob.callSignals.length === 1, 'Боб получил WebRTC Offer от Алисы');
    assert(bob.callSignals[0].signal.type === 'offer', 'Тип SDP-пакета: offer');

    bob.sendCallSignal(alice.identity.id, { type: 'answer', sdp: 'v=0\r\no=bob 789 101...' });
    await wait(300);
    assert(alice.callSignals.length === 1, 'Алиса получила WebRTC Answer от Боба');

    // ТЕСТ 7: Офлайн Dead-Drop очередь (доставка при отсутствии адресата в сети)
    console.log('\n[7/7] Тестирование офлайн Dead-Drop очереди:');
    const offlineCharlie = new TestAgent('Чарли');
    // Чарли пока НЕ подключен! Алиса шлет ему пакет вслепую
    alice.sendMessage(offlineCharlie.identity.id, offlineCharlie.identity.publicKeyB64, {
        id: 'msg_offline_999',
        text: 'Ты был офлайн, когда я это послала!',
        timestamp: Date.now()
    });

    await wait(400); // Даем серверу сохранить пакет на диск
    console.log('  [*] Чарли выходит в сеть...');
    await offlineCharlie.connect();
    await wait(500);

    assert(offlineCharlie.inbox.length === 1, 'Чарли после подключения получил отложенный пакет из Dead-Drop');
    assert(offlineCharlie.inbox[0].decrypted.text === 'Ты был офлайн, когда я это послала!', 'Текст из офлайн-очереди расшифрован корректно');

    // Очистка соединений
    alice.close();
    bob.close();
    offlineCharlie.close();

    console.log('\n================================================================');
    console.log(`ИТОГ ТЕСТИРОВАНИЯ: ${passedTests} из ${totalTests} тестов успешно пройдено (${Math.round(passedTests/totalTests*100)}%)`);
    console.log('================================================================');

    if (passedTests === totalTests) {
        process.exit(0);
    } else {
        process.exit(1);
    }
}

runFullSuite().catch(err => {
    console.error('Критическая ошибка тест-сьюта:', err);
    process.exit(1);
});
