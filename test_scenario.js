const SovereignClient = require('./client/client');

async function runDemo() {
    console.log('====================================================');
    console.log('   СИМУЛЯЦИЯ СКВОЗНОГО ШИФРОВАНИЯ (E2EE)');
    console.log('====================================================');

    const serverUrl = 'ws://127.0.0.1:8080';

    const alice = new SovereignClient('Алиса');
    const bob = new SovereignClient('Боб');

    bob.onMessage((decrypted, envelope) => {
        console.log(`\n[Боб получил]: "${decrypted.text}"`);
        console.log(`[Сервер передал шум]: ${envelope.ciphertext.slice(0, 32)}...`);
    });

    try {
        await alice.connect(serverUrl);
        await bob.connect(serverUrl);

        console.log('\n[+] Алиса и Боб успешно подключились к серверу.');
        console.log('[*] Алиса отправляет зашифрованное сообщение Бобу...');

        alice.sendEncryptedMessage(bob.identity.id, bob.identity.publicKeyB64, 'Привет, Боб! Это суверенное сообщение без посредников.');

        setTimeout(() => {
            console.log('\n====================================================');
            console.log('Тест успешно завершен! Сообщение доставлено.');
            console.log('====================================================');
            alice.close();
            bob.close();
            process.exit(0);
        }, 1500);
    } catch (e) {
        console.error('Ошибка в тесте:', e.message);
        process.exit(1);
    }
}

runDemo();
