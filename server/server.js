// ==============================================================================
// СУВЕРЕННЫЙ СЛЕПОЙ РЕЛЕЙ-СЕРВЕР + АВТОМАТИЧЕСКИЙ ИНТЕРНЕТ-ТУННЕЛЬ
// ==============================================================================

process.on('uncaughtException', (err) => {
    console.error('[UNCAUGHT EXCEPTION]:', err ? (err.stack || err.message || err) : 'Unknown');
});

process.on('unhandledRejection', (reason) => {
    console.error('[UNHANDLED REJECTION]:', reason);
});

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const DATA_DIR = path.join(__dirname, '..', 'data');
const QUEUE_DIR = path.join(DATA_DIR, 'offline_queue');
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.webp': 'image/webp'
};

// Пароль/секрет сервера для доступа "только для своих"
// Можно задать через переменную окружения CIPHER_SERVER_SECRET или оставить дефолтный для локальных тестов
const SERVER_SECRET = process.env.CIPHER_SERVER_SECRET || '';

// Создаем каталоги для персистентного хранения очереди на диске
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(QUEUE_DIR)) fs.mkdirSync(QUEUE_DIR, { recursive: true });

let publicTunnelUrl = process.env.PUBLIC_URL || null;
if (!publicTunnelUrl && process.env.RENDER_EXTERNAL_URL) {
    publicTunnelUrl = process.env.RENDER_EXTERNAL_URL.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:');
}
if (!publicTunnelUrl && process.env.RAILWAY_STATIC_URL) {
    publicTunnelUrl = `wss://${process.env.RAILWAY_STATIC_URL}`;
}

// 1. Легковесный API Сервер (без раздачи статики public/, минимальная нагрузка)
const server = http.createServer((req, res) => {
    const cleanUrl = req.url.split('?')[0];

    // API для получения актуального публичного адреса сервера/туннеля
    if (cleanUrl === '/api/server-info') {
        let effectiveTunnelUrl = publicTunnelUrl;
        if (!effectiveTunnelUrl && req.headers.host && !req.headers.host.includes('localhost') && !req.headers.host.includes('127.0.0.1')) {
            const proto = (req.headers['x-forwarded-proto'] === 'http' || (!req.headers['x-forwarded-proto'] && req.headers.host.includes(':'))) ? 'ws' : 'wss';
            effectiveTunnelUrl = `${proto}://${req.headers.host}`;
        }
        res.writeHead(200, { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        });
        return res.end(JSON.stringify({
            status: 'online',
            localPort: PORT,
            tunnelUrl: effectiveTunnelUrl
        }));
    }

    // Быстрое скачивание Android APK напрямую на телефон
    if (cleanUrl === '/download' || cleanUrl === '/CIPHER.apk') {
        const apkPath = path.join(__dirname, '..', 'CIPHER.apk');
        if (fs.existsSync(apkPath)) {
            const stat = fs.statSync(apkPath);
            res.writeHead(200, {
                'Content-Type': 'application/vnd.android.package-archive',
                'Content-Length': stat.size,
                'Content-Disposition': 'attachment; filename="CIPHER.apk"',
                'Access-Control-Allow-Origin': '*'
            });
            if (req.method === 'HEAD') {
                return res.end();
            }
            return fs.createReadStream(apkPath).pipe(res);
        }
    }

    if (cleanUrl === '/health' || (cleanUrl === '/' && req.headers.accept && req.headers.accept.includes('application/json'))) {
        res.writeHead(200, { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        });
        return res.end(JSON.stringify({
            service: 'CIPHER E2EE Blind Relay',
            status: 'operational',
            tunnel: publicTunnelUrl ? 'active' : 'local_only'
        }));
    }

    // Раздача автономного интерфейса (public/)
    const reqPath = cleanUrl === '/' ? 'index.html' : cleanUrl;
    const safePath = path.normalize(path.join(PUBLIC_DIR, reqPath));
    if (safePath.startsWith(PUBLIC_DIR) && fs.existsSync(safePath) && fs.statSync(safePath).isFile()) {
        const ext = path.extname(safePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';
        res.writeHead(200, {
            'Content-Type': contentType,
            'Access-Control-Allow-Origin': '*'
        });
        return fs.createReadStream(safePath).pipe(res);
    }

    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('CIPHER Relay: 404 Not Found');
});

// 2. Слепой WebSocket релей с сохранением очереди на диск и контролем размера
const wss = new WebSocketServer({ 
    server,
    maxPayload: 25 * 1024 * 1024 // Защита от перегрузки: макс. 25 МБ на пакет
});

const activeClients = new Map(); // clientId -> Set<ws>
const QUEUE_TTL_MS = 3 * 24 * 60 * 60 * 1000; // Храним офлайн-пакеты максимум 3 дня

// Вспомогательные функции для дисковой очереди Dead-Drop
function getClientQueueFilePath(clientId) {
    // Безопасное имя файла из hex-хеша
    const safeName = clientId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
    return path.join(QUEUE_DIR, `${safeName}.json`);
}

function loadOfflineQueue(clientId) {
    const filePath = getClientQueueFilePath(clientId);
    if (!fs.existsSync(filePath)) return [];
    try {
        const raw = fs.readFileSync(filePath, 'utf8');
        const queue = JSON.parse(raw);
        const now = Date.now();
        // Фильтруем просроченные пакеты
        return queue.filter(item => (now - item.timestamp) < QUEUE_TTL_MS);
    } catch (e) {
        return [];
    }
}

function saveOfflineQueue(clientId, queue) {
    const filePath = getClientQueueFilePath(clientId);
    if (!queue || queue.length === 0) {
        if (fs.existsSync(filePath)) {
            try { fs.unlinkSync(filePath); } catch {}
        }
        return;
    }
    try {
        fs.writeFileSync(filePath, JSON.stringify(queue), 'utf8');
    } catch (err) {
        console.error('[ERR] Не удалось сохранить офлайн-очередь на диск:', err.message);
    }
}

function appendToOfflineQueue(clientId, item) {
    const queue = loadOfflineQueue(clientId);
    queue.push(item);
    // Лимит: максимум 100 офлайн-сообщений на одного пользователя, чтобы диск не забился
    if (queue.length > 100) {
        queue.shift(); // Вытесняем самые старые
    }
    saveOfflineQueue(clientId, queue);
}

function broadcastPresence(clientId, isOnline) {
    const msg = JSON.stringify({
        action: 'presence',
        clientId: clientId,
        status: isOnline ? 'online' : 'offline',
        timestamp: Date.now()
    });
    for (const [id, sockets] of activeClients.entries()) {
        if (id !== clientId) {
            for (const sock of sockets) {
                if (sock.readyState === sock.OPEN) {
                    sock.send(msg);
                }
            }
        }
    }
}

function heartbeat() {
    this.isAlive = true;
}

wss.on('connection', (ws, req) => {
    ws.isAlive = true;
    ws.on('pong', heartbeat);

    let authenticatedClientId = null;
    const clientIp = req.socket.remoteAddress;

    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data.toString());

            switch (message.action) {
                case 'register': {
                    const { clientId, serverSecret } = message;

                    // Проверка пароля сервера, если он настроен
                    if (SERVER_SECRET && serverSecret !== SERVER_SECRET) {
                        console.warn(`[!] Отклонено подключение (неверный пароль) с IP: ${clientIp}`);
                        ws.send(JSON.stringify({ error: 'invalid_server_secret' }));
                        ws.close();
                        return;
                    }

                    if (!clientId || typeof clientId !== 'string' || clientId.length < 16) {
                        ws.send(JSON.stringify({ error: 'Неверный clientId' }));
                        return;
                    }

                    authenticatedClientId = clientId;
                    if (!activeClients.has(clientId)) {
                        activeClients.set(clientId, new Set());
                    }
                    activeClients.get(clientId).add(ws);

                    console.log(`[+] В сети: ${clientId.slice(0, 16)}... (IP: ${clientIp})`);

                    // Рассылаем оповещение контактам, что пользователь в сети
                    broadcastPresence(clientId, true);

                    // Проверяем сохраненные на диске пакеты (сообщения и уведомления о прочтении)
                    const pending = loadOfflineQueue(clientId);
                    if (pending.length > 0) {
                        console.log(`[>] Выдача ${pending.length} отложенных пакетов клиенту ${clientId.slice(0, 16)}...`);
                        for (const item of pending) {
                            if (item.type === 'read_receipt') {
                                ws.send(JSON.stringify({
                                    action: 'message_read',
                                    messageId: item.messageId,
                                    readerId: item.readerId,
                                    queuedAt: item.timestamp
                                }));
                            } else {
                                ws.send(JSON.stringify({
                                    action: 'incoming_envelope',
                                    envelope: item.envelope,
                                    queuedAt: item.timestamp,
                                    from: item.from
                                }));
                            }
                        }
                        // СРАЗУ УДАЛЯЕМ С ДИСКА (принцип «доставил — стёр», память свободна)
                        saveOfflineQueue(clientId, []);
                    }

                    // Отправляем список тех, кто сейчас онлайн
                    const onlineIds = Array.from(activeClients.keys());
                    ws.send(JSON.stringify({ 
                        action: 'registered', 
                        status: 'ready',
                        onlineClients: onlineIds
                    }));
                    break;
                }

                case 'send_envelope': {
                    if (!authenticatedClientId) {
                        ws.send(JSON.stringify({ error: 'Требуется регистрация' }));
                        return;
                    }

                    const { to, envelope } = message;
                    if (!to || !envelope) {
                        ws.send(JSON.stringify({ error: 'Поля "to" и "envelope" обязательны' }));
                        return;
                    }

                    const recipientSockets = activeClients.get(to);
                    const envelopeSize = JSON.stringify(envelope).length;

                    console.log(`[INFO] Маршрутизация слепого конверта: ${authenticatedClientId.slice(0, 8)} -> ${to.slice(0, 8)} (${envelopeSize} б)`);

                    let delivered = false;
                    if (recipientSockets && recipientSockets.size > 0) {
                        const packetStr = JSON.stringify({
                            action: 'incoming_envelope',
                            envelope: envelope,
                            from: authenticatedClientId
                        });

                        for (const sock of recipientSockets) {
                            if (sock.readyState === ws.OPEN) {
                                sock.send(packetStr);
                                delivered = true;
                            }
                        }
                    }

                    if (delivered) {
                        ws.send(JSON.stringify({ action: 'ack', status: 'delivered_online', to }));
                    } else {
                        // Сохраняем на диск в Dead-Drop
                        appendToOfflineQueue(to, {
                            envelope: envelope,
                            from: authenticatedClientId,
                            timestamp: Date.now()
                        });
                        ws.send(JSON.stringify({ action: 'ack', status: 'saved_in_dead_drop', to }));
                    }
                    break;
                }

                // Пакет уведомления о прочтении (✓✓) с поддержкой офлайн-очереди
                case 'read_receipt': {
                    if (!authenticatedClientId) return;
                    const { to, messageId } = message;
                    if (!to || !messageId) return;

                    const recipientSockets = activeClients.get(to);
                    let delivered = false;

                    if (recipientSockets && recipientSockets.size > 0) {
                        const receiptPacket = JSON.stringify({
                            action: 'message_read',
                            messageId: messageId,
                            readerId: authenticatedClientId
                        });
                        for (const sock of recipientSockets) {
                            if (sock.readyState === ws.OPEN) {
                                sock.send(receiptPacket);
                                delivered = true;
                            }
                        }
                    }

                    // Если адресат временно офлайн, сохраняем read_receipt в Dead-Drop
                    if (!delivered) {
                        appendToOfflineQueue(to, {
                            type: 'read_receipt',
                            messageId: messageId,
                            readerId: authenticatedClientId,
                            timestamp: Date.now()
                        });
                    }
                    break;
                }

                // Сигнализация WebRTC звонков (Offer / Answer / Candidate / Hangup)
                case 'call_signal': {
                    if (!authenticatedClientId) return;
                    const { to, signal } = message;
                    if (!to || !signal) return;

                    const recipientSockets = activeClients.get(to);
                    if (recipientSockets && recipientSockets.size > 0) {
                        const signalPacket = JSON.stringify({
                            action: 'call_signal',
                            from: authenticatedClientId,
                            signal: signal
                        });
                        for (const sock of recipientSockets) {
                            if (sock.readyState === ws.OPEN) {
                                sock.send(signalPacket);
                            }
                        }
                    }
                    break;
                }

                // Сигнализация статуса набора текста ("печатает...")
                case 'typing': {
                    if (!authenticatedClientId) return;
                    const { to } = message;
                    if (!to) return;

                    const recipientSockets = activeClients.get(to);
                    if (recipientSockets && recipientSockets.size > 0) {
                        const typingPacket = JSON.stringify({
                            action: 'typing',
                            from: authenticatedClientId
                        });
                        for (const sock of recipientSockets) {
                            if (sock.readyState === ws.OPEN) {
                                sock.send(typingPacket);
                            }
                        }
                    }
                    break;
                }

                default:
                    ws.send(JSON.stringify({ error: 'Неизвестная команда' }));
            }
        } catch (err) {
            console.error('[ERR] Ошибка пакета:', err.message);
        }
    });

    ws.on('close', () => {
        if (authenticatedClientId && activeClients.has(authenticatedClientId)) {
            const sockets = activeClients.get(authenticatedClientId);
            sockets.delete(ws);
            if (sockets.size === 0) {
                activeClients.delete(authenticatedClientId);
                console.log(`[-] Клиент отключился: ${authenticatedClientId.slice(0, 16)}...`);
                broadcastPresence(authenticatedClientId, false);
            }
        }
    });

    ws.on('error', (err) => {
        console.error(`[ERR] Ошибка сокета: ${err.message}`);
    });
});

// Регулярный Heartbeat (Ping/Pong) раз в 30 секунд: выявление зависших соединений
const heartbeatInterval = setInterval(() => {
    wss.clients.forEach((ws) => {
        if (ws.isAlive === false) {
            console.log('[!] Обнаружен зависший сокет (таймаут пинга). Принудительное закрытие.');
            return ws.terminate();
        }
        ws.isAlive = false;
        ws.ping();
    });
}, 30000);

wss.on('close', () => {
    clearInterval(heartbeatInterval);
});

// Периодическая очистка просроченных файлов с диска раз в 30 минут
setInterval(() => {
    try {
        if (!fs.existsSync(QUEUE_DIR)) return;
        const files = fs.readdirSync(QUEUE_DIR);
        const now = Date.now();
        for (const file of files) {
            if (!file.endsWith('.json')) continue;
            const fullPath = path.join(QUEUE_DIR, file);
            try {
                const raw = fs.readFileSync(fullPath, 'utf8');
                const queue = JSON.parse(raw);
                const fresh = queue.filter(item => (now - item.timestamp) < QUEUE_TTL_MS);
                if (fresh.length === 0) {
                    fs.unlinkSync(fullPath);
                } else if (fresh.length !== queue.length) {
                    fs.writeFileSync(fullPath, JSON.stringify(fresh), 'utf8');
                }
            } catch {
                try { fs.unlinkSync(fullPath); } catch {}
            }
        }
    } catch (e) {
        console.error('[ERR] Ошибка плановой очистки очереди:', e.message);
    }
}, 30 * 60 * 1000);

// 3. Автоматический запуск Cloudflare Tunnel для доступа из любой точки мира
function startInternetTunnel() {
    if (process.env.DISABLE_TUNNEL === 'true' || process.env.RENDER || process.env.RAILWAY_STATIC_URL) {
        console.log('[TUNNEL] Запуск в постоянном облачном хостинге. Встроенный Cloudflare-туннель отключен.');
        return;
    }

    const cloudflaredPaths = [
        'C:\\Program Files (x86)\\cloudflared\\cloudflared.exe',
        'C:\\Program Files\\cloudflared\\cloudflared.exe',
        'cloudflared'
    ];

    let binary = null;
    for (const p of cloudflaredPaths) {
        if (fs.existsSync(p)) {
            binary = p;
            break;
        }
    }

    if (!binary) {
        console.log('[!] cloudflared не найден. Работает только в локальной сети.');
        return;
    }

    console.log('[...] Подключение защищенного интернет-туннеля Cloudflare...');
    const tunnelProc = spawn(binary, ['tunnel', '--url', `http://127.0.0.1:${PORT}`], {
        stdio: ['ignore', 'pipe', 'pipe']
    });

    function processOutput(chunk) {
        const text = chunk.toString();
        const match = text.match(/https:\/\/([a-zA-Z0-9-]+\.trycloudflare\.com)/);
        if (match && !publicTunnelUrl) {
            const domain = match[1];
            publicTunnelUrl = `wss://${domain}`;
            
            console.log('\n=============================================================');
            console.log('[ СЕРВЕР УСПЕШНО ОПУБЛИКОВАН В ИНТЕРНЕТЕ! ]');
            console.log(`👉  АДРЕС ДЛЯ КЛИЕНТОВ: ${publicTunnelUrl}`);
            console.log('    (Работает через 4G, мобильный интернет и из любого города)');
            console.log('=============================================================\n');

            // Записываем в data/tunnel.json и public/tunnel.json
            try {
                let lanIp = '127.0.0.1';
                try {
                    const ifaces = os.networkInterfaces();
                    for (const name of Object.keys(ifaces)) {
                        for (const net of ifaces[name]) {
                            if (net.family === 'IPv4' && !net.internal && !name.toLowerCase().includes('vpn')) {
                                lanIp = net.address;
                                break;
                            }
                        }
                    }
                } catch {}

                const tunnelData = JSON.stringify({
                    url: publicTunnelUrl,
                    lanUrl: `ws://${lanIp}:${PORT}`,
                    updatedAt: Date.now()
                });
                fs.writeFileSync(path.join(DATA_DIR, 'tunnel.json'), tunnelData);
                fs.writeFileSync(path.join(__dirname, '..', 'public', 'tunnel.json'), tunnelData);
            } catch { }
        }
    }

    tunnelProc.stdout.on('data', processOutput);
    tunnelProc.stderr.on('data', processOutput);

    tunnelProc.on('error', (err) => {
        console.error('[TUNNEL ERR]:', err.message);
    });

    tunnelProc.on('exit', (code) => {
        console.log(`[TUNNEL] Процесс туннеля завершился с кодом ${code}. Перезапуск через 5 сек...`);
        publicTunnelUrl = null;
        setTimeout(startInternetTunnel, 5000);
    });

    process.on('exit', () => {
        try { tunnelProc.kill(); } catch { }
    });
}

server.listen(PORT, '0.0.0.0', () => {
    console.log('====================================================');
    console.log(`[ СУВЕРЕННЫЙ РЕЛЕЙ-СЕРВЕР ЗАПУЩЕН ]`);
    console.log(`Локальный адрес: http://127.0.0.1:${PORT}`);
    console.log('====================================================');
    startInternetTunnel();
});

