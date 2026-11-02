// ==============================================================================
// CIPHER - ZERO-KNOWLEDGE E2EE PROTOCOL (app.js)
// ПК-клиент: Сквозное шифрование, Передача фото, Голосовые сообщения (ГС),
// Drag&Drop, вставка из буфера обмена (Ctrl+V), экспорт ключей.
// ==============================================================================

(async function () {
    'use strict';

    // 1. Инициализация профиля из URL
    const urlParams = new URLSearchParams(window.location.search);
    const currentUserProfile = urlParams.get('user') || 'Алиса';

    const STORAGE_KEY_IDENTITY = `cipher_identity_${currentUserProfile}`;
    const STORAGE_KEY_CONTACTS = `cipher_contacts_${currentUserProfile}`;
    const STORAGE_KEY_MESSAGES = `cipher_messages_${currentUserProfile}`;
    const STORAGE_KEY_OUTBOX = `cipher_outbox_${currentUserProfile}`;
    const STORAGE_KEY_PINNED = `cipher_pinned_${currentUserProfile}`;
    const STORAGE_KEY_DRAFTS = `cipher_drafts_${currentUserProfile}`;
    const STORAGE_KEY_SERVER_URL = 'cipher_server_url';
    const STORAGE_KEY_SERVER_SECRET = 'cipher_server_secret';
    const DEFAULT_SERVER_URL = 'ws://185.219.7.51';

    // ==============================================================================
    // INDEXEDDB STORAGE ENGINE (GIGABYTES CAPACITY FOR PHOTOS/VOICE - NO 5MB LIMIT)
    // ==============================================================================
    const IDB_NAME = 'cipher_e2ee_db';
    const IDB_VERSION = 1;
    const IDB_STORE_KV = 'keyvalue';
    let dbInstance = null;

    function getDb() {
        if (dbInstance) return Promise.resolve(dbInstance);
        return new Promise((resolve) => {
            if (!window.indexedDB) return resolve(null);
            try {
                const req = indexedDB.open(IDB_NAME, IDB_VERSION);
                req.onupgradeneeded = () => {
                    const db = req.result;
                    if (!db.objectStoreNames.contains(IDB_STORE_KV)) {
                        db.createObjectStore(IDB_STORE_KV);
                    }
                };
                req.onsuccess = () => {
                    dbInstance = req.result;
                    resolve(dbInstance);
                };
                req.onerror = () => {
                    console.warn('[IDB] Ошибка доступа к IndexedDB:', req.error);
                    resolve(null);
                };
            } catch (e) {
                console.warn('[IDB] Исключение IndexedDB:', e);
                resolve(null);
            }
        });
    }

    async function idbGet(key) {
        const db = await getDb();
        if (!db) {
            try {
                const item = localStorage.getItem(key);
                return item ? JSON.parse(item) : null;
            } catch { return null; }
        }
        return new Promise((resolve) => {
            try {
                const tx = db.transaction(IDB_STORE_KV, 'readonly');
                const store = tx.objectStore(IDB_STORE_KV);
                const req = store.get(key);
                req.onsuccess = () => resolve(req.result !== undefined ? req.result : null);
                req.onerror = () => resolve(null);
            } catch { resolve(null); }
        });
    }

    async function idbSet(key, value) {
        const db = await getDb();
        if (!db) {
            try { localStorage.setItem(key, JSON.stringify(value)); } catch {}
            return;
        }
        return new Promise((resolve) => {
            try {
                const tx = db.transaction(IDB_STORE_KV, 'readwrite');
                const store = tx.objectStore(IDB_STORE_KV);
                store.put(value, key);
                tx.oncomplete = () => resolve();
                tx.onerror = () => resolve();
            } catch { resolve(); }
        });
    }

    let outboxQueue = []; // Очередь исходящих при обрыве связи { contactId, payload, isGroup, msgId }

    async function drainOutbox() {
        if (!ws || ws.readyState !== WebSocket.OPEN || outboxQueue.length === 0) return;
        console.log(`[OUTBOX] Выгрузка ${outboxQueue.length} исходящих сообщений на релей...`);
        const queueCopy = [...outboxQueue];
        for (const item of queueCopy) {
            try {
                const contact = contacts.find(c => c.id === item.contactId);
                if (!contact) continue;

                if (item.isGroup) {
                    for (const memberId of (contact.memberIds || [])) {
                        if (memberId === identity.id) continue;
                        const memContact = contacts.find(c => c.id === memberId);
                        if (!memContact || !memContact.publicKeyB64) continue;
                        const grpPayload = {
                            ...item.payload,
                            groupId: contact.id,
                            groupName: contact.name
                        };
                        const grpEnv = await WebCryptoE2EE.encryptMessage(memContact.publicKeyB64, grpPayload);
                        ws.send(JSON.stringify({
                            action: 'send_envelope',
                            to: memberId,
                            envelope: grpEnv
                        }));
                    }
                } else {
                    const envelope = await WebCryptoE2EE.encryptMessage(contact.publicKeyB64, item.payload);
                    ws.send(JSON.stringify({
                        action: 'send_envelope',
                        to: contact.id,
                        envelope: envelope
                    }));
                }

                // Снимаем статус ожидания (🕒 -> ✓)
                const chatList = messages[item.contactId] || [];
                const m = chatList.find(msg => msg.id === item.msgId);
                if (m) {
                    m.pending = false;
                }
                const chk = document.getElementById(`status_${item.msgId}`);
                if (chk) chk.textContent = '✓';

                // Удаляем из очереди
                outboxQueue = outboxQueue.filter(q => q.msgId !== item.msgId);
                await idbSet(STORAGE_KEY_OUTBOX, outboxQueue);
                saveMessages();
            } catch (err) {
                console.warn('[OUTBOX] Ошибка отправки пакета:', err);
                break;
            }
        }
        renderContactList();
    }

    let onlineClientIds = new Set();
    let typingUsers = new Set();

    let identity = null;
    let contacts = [];
    let messages = {}; // { [contactId]: Array<Message> }
    let activeContactId = null;
    let ws = null;
    let reconnectTimeout = null;
    let connectionWatchdog = null;
    let wsReconnectDelay = 1500;
    let attachedFile = null; // { name, type, size, data }
    let currentSearchQuery = '';
    let serverTunnelUrl = null;
    let serverLanUrl = null;
    let replyingMessage = null;
    let editingMessageId = null;
    let pinnedMessages = {}; // { [contactId]: messageId }
    let chatDrafts = {}; // { [contactId]: string }
    let inChatSearchQuery = '';
    let inChatSearchMatches = [];
    let inChatSearchIndex = -1;
    let typingSendThrottle = 0;
    let activeForwardMessage = null;
    let unreadScrolledCount = 0;

    // Переменные для записи голосовых сообщений (ГС)
    let mediaRecorder = null;
    let audioChunks = [];
    let audioContext = null;
    let audioSourceNode = null;
    let audioProcessorNode = null;
    let recordedPcmBuffers = [];
    let audioStream = null;
    let voiceRecordingTimer = null;
    let voiceRecordingSeconds = 0;
    let activeAudioPlayer = null; // текущий воспроизводимый HTMLAudioElement

    // DOM Элементы
    const elConnectionDot = document.getElementById('connection-indicator');
    const elConnectionText = document.getElementById('connection-text');
    const elMyName = document.getElementById('my-name');
    const elMyAvatar = document.getElementById('my-avatar');
    const elMyAlgoBadge = document.getElementById('my-algo-badge');
    const elMyIdPreview = document.getElementById('my-id-preview');
    const elReplyPreviewBar = document.getElementById('reply-preview-bar');
    const elReplyPreviewName = document.getElementById('reply-preview-name');
    const elReplyPreviewText = document.getElementById('reply-preview-text');
    const elBtnCancelReply = document.getElementById('btn-cancel-reply');
    const elChatList = document.getElementById('chat-list');
    const elInputSearchChats = document.getElementById('input-search-chats');
    const elServerUrlDisplay = document.getElementById('server-url-display');

    // Окно диалога
    const elChatHeader = document.getElementById('chat-header');
    const elActiveAvatar = document.getElementById('active-avatar');
    const elActiveContactName = document.getElementById('active-contact-name');
    const elMessagesContainer = document.getElementById('messages-container');
    const elEmptyState = document.getElementById('empty-state');
    const elChatInputArea = document.getElementById('chat-input-area');
    const elMessageForm = document.getElementById('message-form');
    const elMessageInput = document.getElementById('message-input');
    const elBtnSend = document.getElementById('btn-send');
    const elDestructTimer = document.getElementById('destruct-timer');
    const elBtnDestructWrapper = document.getElementById('btn-destruct-wrapper');
    const elDestructPillLabel = document.getElementById('destruct-pill-label');

    const elBtnScrollBottom = document.getElementById('btn-scroll-bottom');
    const elScrollUnreadBadge = document.getElementById('scroll-unread-badge');
    const elPinnedBar = document.getElementById('pinned-message-bar');
    const elPinnedSnippet = document.getElementById('pinned-snippet');
    const elBtnUnpinMessage = document.getElementById('btn-unpin-message');
    const elInChatSearchBar = document.getElementById('inchat-search-bar');
    const elInputInChatSearch = document.getElementById('input-inchat-search');
    const elInChatSearchCount = document.getElementById('inchat-search-count');
    const elBtnInChatPrev = document.getElementById('btn-inchat-prev');
    const elBtnInChatNext = document.getElementById('btn-inchat-next');
    const elBtnInChatClose = document.getElementById('btn-inchat-close');
    const elBtnSearchInChat = document.getElementById('btn-search-in-chat');
    const elModalForward = document.getElementById('modal-forward-message');
    const elBtnCloseForward = document.getElementById('btn-close-forward');
    const elBtnCancelForward = document.getElementById('btn-cancel-forward');
    const elForwardPreview = document.getElementById('forward-preview-snippet');
    const elForwardContactList = document.getElementById('forward-contact-list');
    const elBtnClearChatHistory = document.getElementById('btn-clear-chat-history');

    // Функция переключения между кнопкой отправки и микрофоном (Telegram UX)
    function updateSendButtonVisibility() {
        if (!elBtnSend || !elBtnRecordVoice) return;
        const hasText = elMessageInput && elMessageInput.value.trim().length > 0;
        const hasFile = !!attachedFile;
        if (hasText || hasFile) {
            elBtnSend.style.display = 'flex';
            elBtnRecordVoice.style.display = 'none';
        } else {
            elBtnSend.style.display = 'none';
            elBtnRecordVoice.style.display = 'flex';
        }
    }

    // Клик по пилюле самоуничтожения (быстрый цикл таймера без выпадающего списка)
    if (elBtnDestructWrapper && elDestructTimer) {
        const destructOptions = [0, 10, 30, 60, 300];
        const destructLabels = { 0: 'Выкл', 10: '10с', 30: '30с', 60: '1м', 300: '5м' };

        elBtnDestructWrapper.addEventListener('click', () => {
            const currentVal = parseInt(elDestructTimer.value, 10) || 0;
            const nextIdx = (destructOptions.indexOf(currentVal) + 1) % destructOptions.length;
            const nextVal = destructOptions[nextIdx];
            elDestructTimer.value = String(nextVal);
            if (elDestructPillLabel) elDestructPillLabel.textContent = destructLabels[nextVal] || `${nextVal}с`;
            if (nextVal > 0) {
                elBtnDestructWrapper.classList.add('active');
            } else {
                elBtnDestructWrapper.classList.remove('active');
            }
            if (navigator.vibrate) navigator.vibrate(15);
        });
    }

    // Прикрепление фото и файлов
    const elBtnAttachFile = document.getElementById('btn-attach-file');
    const elFileInput = document.getElementById('file-input');
    const elFilePreviewBar = document.getElementById('file-preview-bar');
    const elPreviewImg = document.getElementById('preview-image-elem');
    const elPreviewFileIcon = document.getElementById('preview-file-icon');
    const elFilePreviewName = document.getElementById('file-preview-name');
    const elFilePreviewSize = document.getElementById('file-preview-size');
    const elBtnRemoveAttachment = document.getElementById('btn-remove-attachment');
    const elDropZone = document.getElementById('chat-main-dropzone');
    const elDragOverlay = document.getElementById('drag-drop-overlay');

    // Голосовые сообщения (ГС)
    const elBtnRecordVoice = document.getElementById('btn-record-voice');
    const elVoicePanel = document.getElementById('voice-recording-panel');
    const elVoiceRecTimer = document.getElementById('voice-rec-timer');
    const elBtnCancelVoice = document.getElementById('btn-cancel-voice');
    const elBtnSendVoice = document.getElementById('btn-send-voice');

    // Модальные окна
    const elModalProfile = document.getElementById('modal-profile');
    const elModalAddContact = document.getElementById('modal-add-contact');
    const elModalContactInfo = document.getElementById('modal-contact-info');
    const elModalServerSettings = document.getElementById('modal-server-settings');
    const elModalLightbox = document.getElementById('modal-image-lightbox');
    const elLightboxImg = document.getElementById('lightbox-img');
    const elLightboxFilename = document.getElementById('lightbox-filename');
    const elLightboxDownload = document.getElementById('lightbox-download-link');

    // 2. Инициализация суверенной криптографической личности
    async function initIdentity() {
        const saved = localStorage.getItem(STORAGE_KEY_IDENTITY);
        if (saved) {
            try {
                identity = JSON.parse(saved);
            } catch {
                identity = null;
            }
        }

        if (!identity || !identity.id || !identity.publicKeyB64 || !identity.privateKeyB64) {
            console.log(`[CIPHER] Генерация новой криптографической личности для «${currentUserProfile}»...`);
            identity = await WebCryptoE2EE.generateIdentity();
            identity.name = currentUserProfile;
            localStorage.setItem(STORAGE_KEY_IDENTITY, JSON.stringify(identity));
        }

        const displayName = identity.name || currentUserProfile;
        elMyName.textContent = displayName;
        elMyAvatar.textContent = displayName[0].toUpperCase();
        elMyAvatar.style.background = getColorFromHash(identity.id);
        if (elMyAlgoBadge) elMyAlgoBadge.textContent = identity.algo || 'X25519';
        elMyIdPreview.textContent = `ID: ${identity.id.slice(0, 16)}...`;

        const elDisplayMyId = document.getElementById('display-my-id');
        const elDisplayMyPubkey = document.getElementById('display-my-pubkey');
        const elInputEditMyName = document.getElementById('input-edit-my-name');
        const elInviteLink = document.getElementById('display-my-invite-link');

        if (elDisplayMyId) elDisplayMyId.value = identity.id;
        if (elDisplayMyPubkey) elDisplayMyPubkey.value = identity.publicKeyB64;
        if (elInputEditMyName) elInputEditMyName.value = displayName;

        if (elInviteLink) {
            // Формируем чистую инвайт-ссылку для друзей
            const baseUri = window.location.origin + window.location.pathname;
            const invitePayload = btoa(encodeURIComponent(JSON.stringify({
                name: displayName,
                pub: identity.publicKeyB64
            })));
            elInviteLink.value = `${baseUri}#invite=${invitePayload}`;
        }
    }

    // 3. Загрузка данных контактов и переписок (IndexedDB + плавный перенос)
    async function loadStorageData() {
        try {
            const savedContacts = localStorage.getItem(STORAGE_KEY_CONTACTS);
            contacts = savedContacts ? JSON.parse(savedContacts) : [];
        } catch {
            contacts = [];
        }

        // Загрузка сообщений из IndexedDB (с защитой от 5-10 МБ лимита WebView)
        try {
            let savedMessages = await idbGet(STORAGE_KEY_MESSAGES);
            if (!savedMessages) {
                // Плавная миграция существующей переписки из localStorage
                const legacy = localStorage.getItem(STORAGE_KEY_MESSAGES);
                if (legacy) {
                    savedMessages = JSON.parse(legacy);
                    await idbSet(STORAGE_KEY_MESSAGES, savedMessages);
                    localStorage.removeItem(STORAGE_KEY_MESSAGES);
                    console.log('[IDB] Переписка успешно мигрирована из localStorage в IndexedDB!');
                }
            }
            messages = savedMessages || {};
        } catch (e) {
            console.warn('[IDB] Ошибка загрузки сообщений:', e);
            messages = {};
        }

        // Загрузка очереди исходящих сообщений
        try {
            outboxQueue = (await idbGet(STORAGE_KEY_OUTBOX)) || [];
        } catch {
            outboxQueue = [];
        }

        try {
            pinnedMessages = (await idbGet(STORAGE_KEY_PINNED)) || {};
        } catch {
            pinnedMessages = {};
        }

        try {
            chatDrafts = (await idbGet(STORAGE_KEY_DRAFTS)) || {};
        } catch {
            chatDrafts = {};
        }

        checkAutoPairing();
        checkInviteLink();
        renderContactList();

        if (ws && ws.readyState === WebSocket.OPEN) {
            drainOutbox();
        }
    }

    // Автоматическое добавление контакта по ссылке #invite=...
    async function checkInviteLink() {
        if (!window.location.hash || !window.location.hash.includes('invite=')) return;
        try {
            const rawHash = window.location.hash.split('invite=')[1];
            if (!rawHash) return;
            const decoded = JSON.parse(decodeURIComponent(atob(rawHash)));
            if (decoded.pub && decoded.name) {
                const rawPub = WebCryptoE2EE.b642buf(decoded.pub);
                const hashBuf = await window.crypto.subtle.digest('SHA-256', rawPub);
                const friendId = WebCryptoE2EE.buf2hex(hashBuf);

                if (identity && friendId !== identity.id) {
                    const existing = contacts.find(c => c.id === friendId);
                    if (!existing) {
                        contacts.push({
                            id: friendId,
                            name: decoded.name,
                            publicKeyB64: decoded.pub
                        });
                        saveContacts();
                        selectContact(friendId);
                        // Очищаем хеш из адресной строки для красоты
                        window.history.replaceState(null, '', window.location.pathname + window.location.search);
                        alert(`Собеседник «${decoded.name}» успешно добавлен по инвайт-ссылке!`);
                    }
                }
            }
        } catch (e) {
            console.warn('[INVITE] Не удалось разобрать инвайт-ссылку:', e);
        }
    }

    // Автоматическое взаимное добавление Алисы и Боба для быстрого теста
    function checkAutoPairing() {
        const otherUser = currentUserProfile === 'Алиса' ? 'Боб' : 'Алиса';
        const otherIdentityRaw = localStorage.getItem(`cipher_identity_${otherUser}`);
        if (otherIdentityRaw) {
            try {
                const other = JSON.parse(otherIdentityRaw);
                const exists = contacts.some(c => c.id === other.id);
                if (!exists) {
                    contacts.push({
                        id: other.id,
                        name: other.name || otherUser,
                        publicKeyB64: other.publicKeyB64
                    });
                    localStorage.setItem(STORAGE_KEY_CONTACTS, JSON.stringify(contacts));
                }
            } catch {}
        }
    }

    function saveContacts() {
        localStorage.setItem(STORAGE_KEY_CONTACTS, JSON.stringify(contacts));
        renderContactList();
    }

    function saveMessages() {
        idbSet(STORAGE_KEY_MESSAGES, messages);
    }

    // 4. Определение WebSocket адреса
    function getOptimalWsUrl() {
        let saved = localStorage.getItem(STORAGE_KEY_SERVER_URL);
        // Если сохранен старый недействительный временный туннель Cloudflare или localhost на мобилке — очищаем его!
        if (saved && (saved.includes('trycloudflare.com') || (window.location.protocol === 'http:' && (saved.includes('127.0.0.1') || saved.includes('localhost'))))) {
            localStorage.removeItem(STORAGE_KEY_SERVER_URL);
            saved = null;
        }

        if (saved && saved.trim()) {
            saved = saved.trim();
            if (saved.startsWith('http://')) return saved.replace(/^http:\/\//, 'ws://');
            if (saved.startsWith('https://')) return saved.replace(/^https:\/\//, 'wss://');
            if (!saved.startsWith('ws://') && !saved.startsWith('wss://')) return 'ws://' + saved;
            return saved;
        }

        if (serverTunnelUrl && !serverTunnelUrl.includes('trycloudflare.com')) {
            return serverTunnelUrl;
        }

        if (window.location.protocol === 'https:' && window.location.host && !window.location.host.includes('localhost')) {
            return `wss://${window.location.host}`;
        }

        if (window.location.protocol === 'http:' && window.location.host && !window.location.host.includes('localhost') && !window.location.host.includes('127.0.0.1')) {
            return `ws://${window.location.host}`;
        }

        return DEFAULT_SERVER_URL;
    }

    // 5. Подключение к релей-серверу (с защитой от утечек соединений и повторных сокетов)
    function connectWebSocket() {
        if (reconnectTimeout) {
            clearTimeout(reconnectTimeout);
            reconnectTimeout = null;
        }

        // Если сокет уже подключен или прямо сейчас подключается — не создаем дубликат!
        if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
            return;
        }

        // Полное освобождение старого сокета и его обработчиков
        if (ws) {
            try {
                ws.onopen = null;
                ws.onmessage = null;
                ws.onerror = null;
                ws.onclose = null;
                ws.close();
            } catch {}
            ws = null;
        }

        if (connectionWatchdog) {
            clearTimeout(connectionWatchdog);
            connectionWatchdog = null;
        }

        const wsUrl = getOptimalWsUrl();
        elServerUrlDisplay.textContent = wsUrl.replace('wss://', '').replace('ws://', '');
        elServerUrlDisplay.title = wsUrl;

        elConnectionText.textContent = 'Подключение...';
        elConnectionDot.className = 'pulse-dot';

        connectionWatchdog = setTimeout(() => {
            if (ws && ws.readyState === WebSocket.CONNECTING) {
                console.warn('[WS] Таймаут подключения к ' + wsUrl);
                try { ws.close(); } catch {}
                onWsError('Таймаут (6 сек)', wsUrl);
            }
        }, 6000);

        try {
            ws = new WebSocket(wsUrl);
        } catch (e) {
            if (connectionWatchdog) {
                clearTimeout(connectionWatchdog);
                connectionWatchdog = null;
            }
            onWsError(e, wsUrl);
            return;
        }

        ws.onopen = () => {
            if (connectionWatchdog) {
                clearTimeout(connectionWatchdog);
                connectionWatchdog = null;
            }
            wsReconnectDelay = 1500;
            console.log('[WS] Подключено к релею:', wsUrl);
            elConnectionDot.className = 'pulse-dot online';
            elConnectionText.textContent = 'В сети';

            // Регистрация в слепом релее с паролем сервера
            const savedSecret = localStorage.getItem(STORAGE_KEY_SERVER_SECRET) || '';
            ws.send(JSON.stringify({
                action: 'register',
                clientId: identity.id,
                serverSecret: savedSecret
            }));
        };

        ws.onmessage = async (event) => {
            try {
                const data = JSON.parse(event.data);

                if (data.action === 'registered') {
                    console.log('[WS] Зарегистрирован в релее.');
                    if (Array.isArray(data.onlineClients)) {
                        onlineClientIds = new Set(data.onlineClients);
                        renderContactList();
                    }
                    drainOutbox();
                } else if (data.action === 'presence') {
                    if (data.status === 'online') {
                        onlineClientIds.add(data.clientId);
                    } else {
                        onlineClientIds.delete(data.clientId);
                    }
                    renderContactList();
                } else if (data.action === 'message_read') {
                    handleRemoteReadReceipt(data.messageId);
                } else if (data.action === 'typing') {
                    handleIncomingTyping(data.from);
                } else if (data.action === 'incoming_envelope') {
                    await handleIncomingEnvelope(data.envelope);
                } else if (data.action === 'call_signal') {
                    await handleCallSignal(data.from, data.signal);
                } else if (data.action === 'ack') {
                    console.log('[WS] Доставка пакета:', data.status);
                } else if (data.error === 'invalid_server_secret') {
                    alert('Ошибка: Неверный пароль сервера! Укажите правильный пароль в настройках (шестеренка внизу).');
                }
            } catch (err) {
                console.error('[WS] Ошибка пакета:', err);
            }
        };

        ws.onclose = () => {
            if (connectionWatchdog) {
                clearTimeout(connectionWatchdog);
                connectionWatchdog = null;
            }
            onWsError(null, wsUrl);
        };

        ws.onerror = (err) => {
            if (connectionWatchdog) {
                clearTimeout(connectionWatchdog);
                connectionWatchdog = null;
            }
            onWsError(err, wsUrl);
        };
    }

    function onWsError(err, wsUrl) {
        elConnectionDot.className = 'pulse-dot offline';
        elConnectionText.textContent = 'Офлайн';
        if (!reconnectTimeout) {
            reconnectTimeout = setTimeout(connectWebSocket, wsReconnectDelay);
            wsReconnectDelay = Math.min(wsReconnectDelay * 1.5, 8000);
        }
    }

    // Фоновый запрос информации о внешнем туннеле
    async function fetchServerInfo() {
        try {
            const res = await fetch('/api/server-info');
            if (res.ok) {
                const info = await res.json();
                if (info.tunnelUrl) {
                    serverTunnelUrl = info.tunnelUrl;
                    const tunnelField = document.getElementById('display-tunnel-url-field');
                    if (tunnelField) tunnelField.value = serverTunnelUrl;
                }
            }
        } catch {}

        // Если это мобильное приложение (Capacitor) или локальный файл, читаем встроенный tunnel.json
        if (!serverTunnelUrl) {
            try {
                const tRes = await fetch('tunnel.json');
                if (tRes.ok) {
                    const tInfo = await tRes.json();
                    if (tInfo.url) {
                        serverTunnelUrl = tInfo.url;
                        const tunnelField = document.getElementById('display-tunnel-url-field');
                        if (tunnelField) tunnelField.value = serverTunnelUrl;
                    }
                    if (tInfo.lanUrl) {
                        serverLanUrl = tInfo.lanUrl;
                    }
                    if (!localStorage.getItem(STORAGE_KEY_SERVER_URL) && (!ws || (ws.readyState !== WebSocket.OPEN && ws.readyState !== WebSocket.CONNECTING))) {
                        connectWebSocket();
                    }
                }
            } catch {}
        }
    }
    fetchServerInfo();
    setInterval(fetchServerInfo, 5000);

    // Панель ответа на сообщение (Reply)
    if (elBtnCancelReply) {
        elBtnCancelReply.onclick = clearReply;
    }

    function setReplyToMessage(msg) {
        replyingMessage = msg;
        const senderName = msg.fromMe ? 'Вы' : (contacts.find(c => c.id === activeContactId)?.name || 'Собеседник');
        let preview = msg.text || '';
        if (!preview) {
            if (msg.file) preview = (msg.file.type && msg.file.type.startsWith('image/')) ? '📷 Фотография' : ('📎 ' + (msg.file.name || 'Файл'));
            else if (msg.voice) preview = '🎤 Голосовое сообщение';
            else preview = 'Сообщение';
        }
        if (elReplyPreviewName) elReplyPreviewName.textContent = senderName;
        if (elReplyPreviewText) elReplyPreviewText.textContent = preview;
        if (elReplyPreviewBar) elReplyPreviewBar.style.display = 'flex';
        if (elMessageInput) elMessageInput.focus();
    }

    function clearReply() {
        replyingMessage = null;
        if (elReplyPreviewBar) elReplyPreviewBar.style.display = 'none';
    }

    window.triggerReply = function(msgId) {
        const msgs = messages[activeContactId] || [];
        const found = msgs.find(m => m.id === msgId);
        if (found) setReplyToMessage(found);
    };

    window.jumpToMessage = function(targetId) {
        const targetEl = document.getElementById(`msg_el_${targetId}`);
        if (targetEl) {
            targetEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
            targetEl.classList.remove('message-highlight-pulse');
            void targetEl.offsetWidth;
            targetEl.classList.add('message-highlight-pulse');
        }
    };

    // 6. Обработка входящего пакета (E2EE)
    async function handleIncomingEnvelope(envelope) {
        try {
            const decrypted = await WebCryptoE2EE.decryptMessage(identity.privateKeyB64, envelope);
            const senderId = decrypted.senderId;

            // 1. Обработка удаления сообщения у собеседника (Delete for Everyone)
            if (decrypted.type === 'delete_message' && decrypted.targetMessageId) {
                const targetId = decrypted.targetMessageId;
                const chatKey = decrypted.groupId || senderId;
                if (messages[chatKey]) {
                    messages[chatKey] = messages[chatKey].filter(m => m.id !== targetId);
                    saveMessages();
                }
                const el = document.getElementById(`msg_el_${targetId}`);
                if (el) {
                    el.style.transition = 'all 0.25s';
                    el.style.opacity = '0';
                    el.style.transform = 'scale(0.85)';
                    setTimeout(() => el.remove(), 250);
                }
                renderContactList();
                return;
            }

            // 2. Обработка редактирования сообщения (Edit Message)
            if (decrypted.type === 'edit_message' && decrypted.targetMessageId) {
                const targetId = decrypted.targetMessageId;
                const chatKey = decrypted.groupId || senderId;
                const msg = (messages[chatKey] || []).find(m => m.id === targetId);
                if (msg) {
                    msg.text = decrypted.newText;
                    msg.isEdited = true;
                    saveMessages();
                    const textEl = document.querySelector(`#msg_el_${targetId} .message-text`);
                    if (textEl) {
                        textEl.textContent = decrypted.newText;
                        const meta = document.querySelector(`#msg_el_${targetId} .message-meta`);
                        if (meta && !meta.querySelector('.edited-badge')) {
                            const edSpan = document.createElement('span');
                            edSpan.className = 'edited-badge';
                            edSpan.textContent = 'ред. ';
                            edSpan.style.fontSize = '10px';
                            edSpan.style.opacity = '0.7';
                            edSpan.style.marginRight = '4px';
                            meta.prepend(edSpan);
                        }
                    }
                    renderContactList();
                }
                return;
            }

            // 3. Обработка реакций (Emoji Reactions Telegram style)
            if (decrypted.type === 'reaction' && decrypted.targetMessageId && decrypted.emoji) {
                const chatKey = decrypted.groupId || senderId;
                const msg = (messages[chatKey] || []).find(m => m.id === decrypted.targetMessageId);
                if (msg) {
                    if (!msg.reactions) msg.reactions = {};
                    if (!msg.reactions[decrypted.emoji]) msg.reactions[decrypted.emoji] = [];
                    const idx = msg.reactions[decrypted.emoji].indexOf(senderId);
                    if (idx >= 0) {
                        msg.reactions[decrypted.emoji].splice(idx, 1);
                        if (msg.reactions[decrypted.emoji].length === 0) {
                            delete msg.reactions[decrypted.emoji];
                        }
                    } else {
                        msg.reactions[decrypted.emoji].push(senderId);
                    }
                    saveMessages();
                    const rBox = document.getElementById(`reactions_${decrypted.targetMessageId}`);
                    if (rBox) rBox.innerHTML = renderReactionsHtml(msg.reactions, msg.id);
                }
                return;
            }

            // 4. Обработка закрепления сообщения (Pinned Message Telegram style)
            if (decrypted.type === 'pin_message') {
                const chatKey = decrypted.groupId || senderId;
                if (decrypted.unpin) {
                    delete pinnedMessages[chatKey];
                } else if (decrypted.targetMessageId) {
                    pinnedMessages[chatKey] = decrypted.targetMessageId;
                }
                idbSet(STORAGE_KEY_PINNED, pinnedMessages);
                if (activeContactId === chatKey) {
                    updatePinnedBanner(chatKey);
                }
                return;
            }

            const isGroup = !!decrypted.groupId;
            const chatKey = isGroup ? decrypted.groupId : senderId;

            let contact = contacts.find(c => c.id === chatKey);
            if (isGroup) {
                if (!contact) {
                    contact = {
                        id: decrypted.groupId,
                        name: decrypted.groupName || 'Группа',
                        isGroup: true,
                        memberIds: [senderId, identity.id]
                    };
                    contacts.push(contact);
                    saveContacts();
                }
            } else {
                if (!contact && decrypted.senderPublicKeyB64) {
                    contact = {
                        id: senderId,
                        name: `Собеседник (${senderId.slice(0, 6)})`,
                        publicKeyB64: decrypted.senderPublicKeyB64
                    };
                    contacts.push(contact);
                    saveContacts();
                }
            }

            if (!messages[chatKey]) {
                messages[chatKey] = [];
            }

            // Нормализация фото / файла
            let fileObj = decrypted.file || null;
            if (!fileObj && decrypted.photo) {
                let photoData = decrypted.photo;
                if (!photoData.startsWith('data:')) {
                    photoData = 'data:image/jpeg;base64,' + photoData;
                }
                fileObj = {
                    name: 'photo.jpg',
                    type: 'image/jpeg',
                    size: Math.round(photoData.length * 0.75),
                    data: photoData
                };
            }

            // Нормализация голосового сообщения (ГС)
            let voiceObj = decrypted.voice || null;
            if (voiceObj && typeof voiceObj === 'string') {
                let vData = voiceObj;
                if (!vData.startsWith('data:')) {
                    vData = 'data:audio/wav;base64,' + vData;
                }
                voiceObj = {
                    data: vData,
                    duration: decrypted.voiceDuration || 0
                };
            } else if (voiceObj && typeof voiceObj === 'object' && voiceObj.data) {
                if (!voiceObj.data.startsWith('data:')) {
                    voiceObj.data = 'data:audio/wav;base64,' + voiceObj.data;
                }
            }

            // Нормализация времени
            let ts = decrypted.timestamp || Date.now();
            if (ts > 5000000000000) {
                ts = Math.round((ts - 621355968000000000) / 10000);
            }

            const msgId = (decrypted.id && typeof decrypted.id === 'string') 
                ? decrypted.id 
                : ('msg_' + ts + '_' + Math.random().toString(36).substr(2, 6));

            const msgObj = {
                id: msgId,
                fromMe: false,
                senderId: senderId,
                senderName: decrypted.senderName || (contact ? contact.name : 'Собеседник'),
                text: decrypted.text || '',
                file: fileObj,
                voice: voiceObj,
                timestamp: ts,
                destructSeconds: decrypted.destructSeconds || 0,
                cipherDebug: envelope.ciphertext ? envelope.ciphertext.slice(0, 48) + '...' : '',
                replyToId: decrypted.replyToId || null,
                replyPreviewText: decrypted.replyPreviewText || null,
                replySenderName: decrypted.replySenderName || null,
                reactions: decrypted.reactions || {},
                forwardedFrom: decrypted.forwardedFrom || null,
                isRead: (activeContactId === chatKey && !document.hidden)
            };

            messages[chatKey].push(msgObj);
            saveMessages();
            renderContactList();

            if (activeContactId === chatKey) {
                appendMessageToUI(msgObj);
                if (isNearBottom()) {
                    scrollToBottom(true);
                } else {
                    unreadScrolledCount++;
                    updateScrollBottomButton();
                }

                if (!document.hidden && ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({
                        action: 'read_receipt',
                        to: senderId,
                        messageId: msgId
                    }));
                }
            }

            // Системное Push/Web уведомление при скрытом экране или в неактивном чате
            if (document.hidden || activeContactId !== chatKey) {
                const notifTitle = isGroup ? `${msgObj.senderName} (${contact.name})` : (contact ? contact.name : 'Собеседник');
                const notifBody = msgObj.text || (fileObj ? `📄 ${fileObj.name}` : (voiceObj ? '🎤 Голосовое сообщение' : 'Вложение'));
                triggerMessageNotification(notifTitle, notifBody);
            }

            playReceiveSound();

            if (msgObj.destructSeconds > 0) {
                startSelfDestructCountdown(msgObj, chatKey);
            }
        } catch (err) {
            console.error('[E2EE] Ошибка дешифрования пакета:', err);
        }
    }

    // 7. Отправка E2EE сообщения / фото / голосового
    async function sendMessage(text, voicePayload = null, overrideFile = null, forwardedFrom = null) {
        if (!activeContactId) {
            alert('Пожалуйста, выберите чат из списка слева.');
            return;
        }

        const effFile = overrideFile || attachedFile;
        if (!text.trim() && !effFile && !voicePayload) {
            return;
        }

        const contact = contacts.find(c => c.id === activeContactId);
        if (!contact) return;

        const isOnline = !!(ws && ws.readyState === WebSocket.OPEN);

        // Редактирование существующего сообщения
        if (editingMessageId) {
            const editTargetId = editingMessageId;
            const targetMsg = (messages[activeContactId] || []).find(m => m.id === editTargetId);
            if (targetMsg) {
                targetMsg.text = text.trim();
                targetMsg.isEdited = true;
                saveMessages();
                const textEl = document.querySelector(`#msg_el_${editTargetId} .message-text`);
                if (textEl) {
                    textEl.textContent = text.trim();
                    const meta = document.querySelector(`#msg_el_${editTargetId} .message-meta`);
                    if (meta && !meta.querySelector('.edited-badge')) {
                        const edSpan = document.createElement('span');
                        edSpan.className = 'edited-badge';
                        edSpan.textContent = 'ред. ';
                        edSpan.style.fontSize = '10px';
                        edSpan.style.opacity = '0.7';
                        edSpan.style.marginRight = '4px';
                        meta.prepend(edSpan);
                    }
                }

                if (isOnline) {
                    if (contact.isGroup) {
                        for (const memberId of (contact.memberIds || [])) {
                            if (memberId === identity.id) continue;
                            const memContact = contacts.find(c => c.id === memberId);
                            if (!memContact || !memContact.publicKeyB64) continue;
                            const editPayload = {
                                type: 'edit_message',
                                targetMessageId: editTargetId,
                                newText: text.trim(),
                                groupId: contact.id,
                                senderId: identity.id,
                                senderPublicKeyB64: identity.publicKeyB64,
                                timestamp: Date.now()
                            };
                            const envelope = await WebCryptoE2EE.encryptMessage(memContact.publicKeyB64, editPayload);
                            ws.send(JSON.stringify({
                                action: 'send_envelope',
                                to: memberId,
                                envelope: envelope
                            }));
                        }
                    } else {
                        const editPayload = {
                            type: 'edit_message',
                            targetMessageId: editTargetId,
                            newText: text.trim(),
                            senderId: identity.id,
                            senderPublicKeyB64: identity.publicKeyB64,
                            timestamp: Date.now()
                        };
                        const envelope = await WebCryptoE2EE.encryptMessage(contact.publicKeyB64, editPayload);
                        ws.send(JSON.stringify({
                            action: 'send_envelope',
                            to: contact.id,
                            envelope: envelope
                        }));
                    }
                }
            }
            cancelEditMessage();
            renderContactList();
            return;
        }

        const destructTime = parseInt(elDestructTimer.value, 10) || 0;
        const nowMs = Date.now();
        const msgId = 'msg_' + nowMs + '_' + Math.random().toString(36).substr(2, 6);

        // Формирование данных ответа (Reply)
        let rToId = null, rPrev = null, rSender = null;
        if (replyingMessage) {
            rToId = replyingMessage.id;
            rSender = replyingMessage.fromMe ? 'Вы' : (contact.name || 'Собеседник');
            rPrev = replyingMessage.text || '';
            if (!rPrev) {
                if (replyingMessage.file) rPrev = (replyingMessage.file.type && replyingMessage.file.type.startsWith('image/')) ? '📷 Фотография' : ('📎 ' + (replyingMessage.file.name || 'Файл'));
                else if (replyingMessage.voice) rPrev = '🎤 Голосовое сообщение';
                else rPrev = 'Сообщение';
            }
        }

        const payload = {
            id: msgId,
            text: text.trim(),
            file: effFile ? { ...effFile } : null,
            photo: (effFile && effFile.type && effFile.type.startsWith('image/')) ? (effFile.data.includes(',') ? effFile.data.split(',')[1] : effFile.data) : null,
            voice: voicePayload ? { ...voicePayload } : null,
            voiceDuration: voicePayload ? (voicePayload.duration || 0) : 0,
            senderId: identity.id,
            senderName: identity.name,
            senderPublicKeyB64: identity.publicKeyB64,
            timestamp: nowMs,
            destructSeconds: destructTime,
            replyToId: rToId,
            replyPreviewText: rPrev,
            replySenderName: rSender,
            forwardedFrom: forwardedFrom || null
        };

        let cipherPreview = '';

        if (isOnline) {
            try {
                if (contact.isGroup) {
                    for (const memberId of (contact.memberIds || [])) {
                        if (memberId === identity.id) continue;
                        const memContact = contacts.find(c => c.id === memberId);
                        if (!memContact || !memContact.publicKeyB64) continue;
                        const grpPayload = {
                            ...payload,
                            groupId: contact.id,
                            groupName: contact.name
                        };
                        const grpEnv = await WebCryptoE2EE.encryptMessage(memContact.publicKeyB64, grpPayload);
                        ws.send(JSON.stringify({
                            action: 'send_envelope',
                            to: memberId,
                            envelope: grpEnv
                        }));
                    }
                    cipherPreview = '👥 Fan-Out [' + (contact.memberIds ? contact.memberIds.length : 0) + ' участн.]';
                } else {
                    const envelope = await WebCryptoE2EE.encryptMessage(contact.publicKeyB64, payload);
                    ws.send(JSON.stringify({
                        action: 'send_envelope',
                        to: contact.id,
                        envelope: envelope
                    }));
                    cipherPreview = envelope.ciphertext ? envelope.ciphertext.slice(0, 48) + '...' : '';
                }
            } catch (err) {
                console.warn('[WS] Ошибка отправки, добавление в исходящие:', err);
                outboxQueue.push({ contactId: activeContactId, payload, isGroup: !!contact.isGroup, msgId });
                idbSet(STORAGE_KEY_OUTBOX, outboxQueue);
                cipherPreview = 'Ожидает отправки (Outbox)';
            }
        } else {
            // Офлайн: сохраняем в очередь исходящих (Outbox)
            outboxQueue.push({ contactId: activeContactId, payload, isGroup: !!contact.isGroup, msgId });
            idbSet(STORAGE_KEY_OUTBOX, outboxQueue);
            cipherPreview = 'Ожидает подключения (Outbox)';
        }

        const msgObj = {
            id: msgId,
            fromMe: true,
            text: text.trim(),
            file: effFile ? { ...effFile } : null,
            voice: voicePayload ? { ...voicePayload } : null,
            timestamp: nowMs,
            destructSeconds: destructTime,
            cipherDebug: cipherPreview,
            replyToId: rToId,
            replyPreviewText: rPrev,
            replySenderName: rSender,
            reactions: {},
            forwardedFrom: forwardedFrom || null,
            pending: !isOnline
        };

        if (!messages[activeContactId]) {
            messages[activeContactId] = [];
        }
        messages[activeContactId].push(msgObj);
        saveMessages();

        delete chatDrafts[activeContactId];
        idbSet(STORAGE_KEY_DRAFTS, chatDrafts);

        appendMessageToUI(msgObj);
        scrollToBottom(true);
        renderContactList();

        playSendSound();

        // Сброс прикрепленного файла и панели ответа
        if (!overrideFile) {
            clearAttachedFile();
        }
        clearReply();

        if (destructTime > 0) {
            startSelfDestructCountdown(msgObj, activeContactId);
        }
    }

    // 8. Таймер самоуничтожения сообщений
    function startSelfDestructCountdown(msgObj, contactId) {
        let remaining = msgObj.destructSeconds;
        const interval = setInterval(() => {
            remaining--;
            const timerEl = document.getElementById(`burn_${msgObj.id}`);
            if (timerEl) {
                timerEl.textContent = `💥 ${remaining}с`;
            }

            if (remaining <= 0) {
                clearInterval(interval);
                if (messages[contactId]) {
                    messages[contactId] = messages[contactId].filter(m => m.id !== msgObj.id);
                    saveMessages();
                }
                const msgDom = document.getElementById(`msg_el_${msgObj.id}`);
                if (msgDom) {
                    msgDom.style.transition = 'all 0.4s ease-out';
                    msgDom.style.opacity = '0';
                    msgDom.style.transform = 'scale(0.8)';
                    setTimeout(() => msgDom.remove(), 400);
                }
            }
        }, 1000);
    }

    // 9. Отрисовка списка чатов с поисковым фильтром
    function renderContactList() {
        elChatList.innerHTML = '';

        let filtered = contacts;
        if (currentSearchQuery) {
            const q = currentSearchQuery.toLowerCase();
            filtered = contacts.filter(c => 
                (c.name && c.name.toLowerCase().includes(q)) || 
                (c.id && c.id.toLowerCase().includes(q))
            );
        }

        if (contacts.length === 0) {
            elChatList.innerHTML = `
                <div style="padding: 30px 20px; text-align: center; color: var(--text-dim); font-size: 13px; line-height: 1.6;">
                    У вас пока нет контактов.<br>
                    Нажмите <strong>«+ Добавить контакт»</strong> для начала переписки.
                </div>
            `;
            return;
        }

        if (filtered.length === 0) {
            elChatList.innerHTML = `
                <div style="padding: 24px 16px; text-align: center; color: var(--text-dim); font-size: 13px;">
                    Контакты не найдены
                </div>
            `;
            return;
        }

        filtered.forEach(contact => {
            const contactMsgs = messages[contact.id] || [];
            const lastMsg = contactMsgs[contactMsgs.length - 1];
            let lastText = 'Чат защищен E2EE';
            let isCustomHtml = false;

            if (typingUsers.has(contact.id)) {
                lastText = '<span class="typing-indicator-row"><span class="typing-dot"></span><span class="typing-dot"></span><span class="typing-dot"></span> печатает...</span>';
                isCustomHtml = true;
            } else if (chatDrafts[contact.id] && chatDrafts[contact.id].trim() && contact.id !== activeContactId) {
                lastText = '<span class="chat-draft-preview">Черновик: ' + escapeHtml(chatDrafts[contact.id].trim()) + '</span>';
                isCustomHtml = true;
            } else if (lastMsg) {
                const prefix = lastMsg.fromMe ? 'Вы: ' : '';
                if (lastMsg.text) {
                    lastText = prefix + lastMsg.text;
                } else if (lastMsg.voice) {
                    lastText = prefix + '🎙️ Голосовое сообщение (' + formatAudioTime(lastMsg.voice.duration || 0) + ')';
                } else if (lastMsg.file) {
                    lastText = prefix + (lastMsg.file.type.startsWith('image/') ? '📷 Фотография' : '📎 ' + lastMsg.file.name);
                }
            }
            const lastTime = lastMsg ? new Date(lastMsg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';

            const isOnline = onlineClientIds.has(contact.id);
            const onlineDot = isOnline ? '<span class="status-badge-online" style="display:block;"></span>' : '';

            const item = document.createElement('div');
            item.className = `chat-item ${contact.id === activeContactId ? 'active' : ''}`;
            item.innerHTML = `
                <div class="avatar-wrapper" style="position: relative;">
                    <div class="avatar" style="background: ${getColorFromHash(contact.id)}">${escapeHtml(contact.name[0].toUpperCase())}</div>
                    ${onlineDot}
                </div>
                <div class="chat-item-info">
                    <div class="chat-item-header">
                        <span class="chat-item-name">${escapeHtml(contact.name)}</span>
                        <span class="chat-item-time">${lastTime}</span>
                    </div>
                    <div class="chat-item-preview">${isCustomHtml ? lastText : escapeHtml(lastText)}</div>
                </div>
            `;

            item.onclick = () => selectContact(contact.id);

            // Долгий тап на контакт (вызов меню управления контактом)
            let cStartX = 0, cStartY = 0, cMoved = false, cTimer = null;
            item.addEventListener('touchstart', (e) => {
                if (e.touches.length !== 1) return;
                cStartX = e.touches[0].clientX;
                cStartY = e.touches[0].clientY;
                cMoved = false;
                cTimer = setTimeout(() => {
                    if (!cMoved) {
                        if (navigator.vibrate) navigator.vibrate(28);
                        activeContactId = contact.id;
                        openContextMenuForTarget(item, cStartX, cStartY);
                    }
                }, 450);
            }, { passive: true });
            item.addEventListener('touchmove', (e) => {
                if (Math.abs(e.touches[0].clientX - cStartX) > 10 || Math.abs(e.touches[0].clientY - cStartY) > 10) {
                    cMoved = true;
                    clearTimeout(cTimer);
                }
            }, { passive: true });
            item.addEventListener('touchend', () => clearTimeout(cTimer), { passive: true });

            elChatList.appendChild(item);
        });
    }

    // 10. Выбор активного диалога
    function selectContact(contactId) {
        if (activeContactId && activeContactId !== contactId && elMessageInput) {
            const currentDraft = elMessageInput.value;
            if (currentDraft && currentDraft.trim()) {
                chatDrafts[activeContactId] = currentDraft;
            } else {
                delete chatDrafts[activeContactId];
            }
            idbSet(STORAGE_KEY_DRAFTS, chatDrafts);
        }

        if (activeAudioPlayer) {
            try { activeAudioPlayer.pause(); } catch {}
            activeAudioPlayer = null;
        }

        activeContactId = contactId;
        unreadScrolledCount = 0;
        updateScrollBottomButton();
        closeInChatSearch();

        const contact = contacts.find(c => c.id === contactId);
        if (!contact) return;

        const appContainer = document.getElementById('app-container');
        if (appContainer) appContainer.classList.add('has-active-chat');

        elEmptyState.style.display = 'none';
        elChatHeader.style.display = 'flex';
        elChatInputArea.style.display = 'block';

        elActiveContactName.textContent = contact.name;
        elActiveAvatar.textContent = contact.name[0].toUpperCase();
        elActiveAvatar.style.background = getColorFromHash(contact.id);

        if (window.history && window.history.pushState) {
            window.history.pushState({ chat: contactId }, '');
        }

        // Восстановление черновика в поле ввода
        if (elMessageInput) {
            elMessageInput.value = chatDrafts[contactId] || '';
            elMessageInput.style.height = 'auto';
            if (elMessageInput.value.length > 0) {
                elMessageInput.style.height = Math.min(elMessageInput.scrollHeight, 120) + 'px';
            }
            updateSendButtonVisibility();
        }

        // Обновление баннера закрепленного сообщения
        updatePinnedBanner(contactId);

        renderContactList();
        renderMessages();

        // Отправка отчетов о прочтении для непрочитанных входящих
        const chatList = messages[contactId] || [];
        let markedRead = false;
        chatList.forEach(m => {
            if (!m.fromMe && !m.isRead) {
                m.isRead = true;
                markedRead = true;
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({
                        action: 'read_receipt',
                        to: m.senderId || contactId,
                        messageId: m.id
                    }));
                }
            }
        });
        if (markedRead) saveMessages();

        if (elMessageInput) elMessageInput.focus();
    }

    function deselectContact() {
        if (activeContactId && elMessageInput) {
            const currentDraft = elMessageInput.value;
            if (currentDraft && currentDraft.trim()) {
                chatDrafts[activeContactId] = currentDraft;
            } else {
                delete chatDrafts[activeContactId];
            }
            idbSet(STORAGE_KEY_DRAFTS, chatDrafts);
        }

        if (activeAudioPlayer) {
            try { activeAudioPlayer.pause(); } catch {}
            activeAudioPlayer = null;
        }

        activeContactId = null;
        unreadScrolledCount = 0;
        updateScrollBottomButton();
        closeInChatSearch();

        const appContainer = document.getElementById('app-container');
        if (appContainer) appContainer.classList.remove('has-active-chat');
        elEmptyState.style.display = 'flex';
        elChatHeader.style.display = 'none';
        elChatInputArea.style.display = 'none';
        renderContactList();
    }

    const btnBackToChats = document.getElementById('btn-back-to-chats');
    if (btnBackToChats) {
        btnBackToChats.addEventListener('click', deselectContact);
    }

    // 11. Отрисовка сообщений
    function renderMessages() {
        elMessagesContainer.innerHTML = '';
        const list = messages[activeContactId] || [];

        list.forEach(msg => appendMessageToUI(msg));
        scrollToBottom();
    }

    function appendMessageToUI(msg) {
        const row = document.createElement('div');
        row.id = `msg_el_${msg.id}`;
        row.className = `message-row ${msg.fromMe ? 'me' : 'other'}`;

        const timeStr = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const burnBadge = msg.destructSeconds > 0 ? `<span class="burn-badge" id="burn_${msg.id}">💥 ${msg.destructSeconds}с</span>` : '';
        const senderTitleHtml = (!msg.fromMe && msg.senderName && contacts.find(c => c.id === activeContactId && c.isGroup))
            ? `<div style="font-size: 11px; font-weight: 700; color: #a5b4fc; margin-bottom: 3px;">${escapeHtml(msg.senderName)}</div>`
            : '';
        const editedHtml = msg.isEdited ? `<span class="edited-badge" style="font-size: 10px; opacity: 0.7; margin-right: 4px;">ред.</span>` : '';

        // 1. Блок фото или файла
        let fileHtml = '';
        if (msg.file && msg.file.data) {
            if (msg.file.type && msg.file.type.startsWith('image/')) {
                fileHtml = `<img src="${msg.file.data}" class="chat-attachment-img" alt="${escapeHtml(msg.file.name)}" onclick="openLightbox('${msg.file.data}', '${escapeHtml(msg.file.name)}')">`;
            } else {
                fileHtml = `
                    <a href="${msg.file.data}" download="${escapeHtml(msg.file.name)}" class="chat-attachment-file">
                        <span style="font-size: 22px;">📄</span>
                        <div style="min-width: 0;">
                            <div style="font-size: 13px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(msg.file.name)}</div>
                            <div style="font-size: 10.5px; color: var(--text-dim); font-family: var(--font-mono);">${formatBytes(msg.file.size)}</div>
                        </div>
                    </a>
                `;
            }
        }

        // 2. Блок голосового сообщения (ГС)
        let voiceHtml = '';
        if (msg.voice && msg.voice.data) {
            const dur = Math.round(msg.voice.duration || 0);
            voiceHtml = `
                <div class="voice-note-player" id="voice_player_${msg.id}">
                    <button type="button" class="voice-play-btn" onclick="playVoiceNote('${msg.id}', '${msg.voice.data}')" id="voice_btn_${msg.id}" aria-label="Воспроизвести">
                        <svg class="voice-icon-play" viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M8 5.14v14l11-7-11-7z"/></svg>
                        <svg class="voice-icon-pause" viewBox="0 0 24 24" width="16" height="16" fill="currentColor" style="display:none;"><path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/></svg>
                    </button>
                    <div class="voice-track-info">
                        <div class="voice-progress-bar" onclick="seekVoiceTrack(event, '${msg.id}')">
                            <div class="voice-progress-fill" id="voice_fill_${msg.id}"></div>
                        </div>
                        <div class="voice-meta-row">
                            <span id="voice_cur_${msg.id}">0:00</span>
                            <div class="voice-right-meta">
                                <span>${formatAudioTime(dur)}</span>
                                <button type="button" class="voice-speed-btn" onclick="cycleVoiceSpeed('${msg.id}', event)" id="speed_${msg.id}">1x</button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        const textHtml = msg.text ? `<div class="message-text">${escapeHtml(msg.text)}</div>` : '';
        const forwardedHtml = msg.forwardedFrom ? `<div style="font-size: 11px; font-style: italic; color: #a5b4fc; margin-bottom: 3px;">Переслано от ${escapeHtml(msg.forwardedFrom)}</div>` : '';

        // 3. Блок цитирования (Reply / Цитата)
        let replyHtml = '';
        if (msg.replyToId) {
            replyHtml = `
                <div class="message-quote-box" onclick="window.jumpToMessage('${escapeHtml(msg.replyToId)}')">
                    <div class="message-quote-line"></div>
                    <div class="message-quote-body">
                        <div class="message-quote-name">${escapeHtml(msg.replySenderName || 'Сообщение')}</div>
                        <div class="message-quote-text">${escapeHtml(msg.replyPreviewText || '...')}</div>
                    </div>
                </div>
            `;
        }

        const quickReactionsHtml = `
            <div class="quick-reactions-bar">
                <button type="button" class="quick-reaction-btn" onclick="toggleReaction('${msg.id}', '👍')">👍</button>
                <button type="button" class="quick-reaction-btn" onclick="toggleReaction('${msg.id}', '❤️')">❤️</button>
                <button type="button" class="quick-reaction-btn" onclick="toggleReaction('${msg.id}', '🔥')">🔥</button>
                <button type="button" class="quick-reaction-btn" onclick="toggleReaction('${msg.id}', '👏')">👏</button>
                <button type="button" class="quick-reaction-btn" onclick="toggleReaction('${msg.id}', '😂')">😂</button>
                <button type="button" class="quick-reaction-btn" onclick="toggleReaction('${msg.id}', '😮')">😮</button>
            </div>
        `;
        const reactionsHtml = `<div class="message-reactions" id="reactions_${msg.id}">${renderReactionsHtml(msg.reactions, msg.id)}</div>`;

        row.innerHTML = `
            <div class="message-bubble">
                ${quickReactionsHtml}
                ${forwardedHtml}
                ${senderTitleHtml}
                ${replyHtml}
                ${textHtml}
                ${fileHtml}
                ${voiceHtml}
                ${reactionsHtml}
                <div class="message-meta">
                    ${burnBadge}
                    ${editedHtml}
                    <span>${timeStr}</span>
                    <span class="msg-status-check" id="status_${msg.id}">${msg.fromMe ? (msg.pending ? '🕒' : (msg.isRead ? '✓✓' : '✓')) : ''}</span>
                    <button type="button" class="btn-bubble-reply" title="Ответить" onclick="window.triggerReply('${msg.id}')">↩</button>
                </div>
                <button class="cipher-toggle" onclick="toggleCipher('${msg.id}')">Показать E2EE конверт</button>
                <div class="cipher-debug-box" id="cipher_${msg.id}" style="display: none;">
                    Сервер передал зашифрованный шум: [${msg.cipherDebug || 'AES-256-GCM'}]
                </div>
            </div>
        `;

        row.ondblclick = (e) => {
            e.stopPropagation();
            setReplyToMessage(msg);
        };

        // Защита от потери скролла при асинхронной загрузке картинок
        row.querySelectorAll('img').forEach(img => {
            img.addEventListener('load', () => {
                if (isNearBottom(250) || msg.fromMe) {
                    scrollToBottom(false);
                }
            }, { once: true });
        });

        // Нативные мобильные жесты (Swipe-to-Reply и Long-Press меню)
        let mTouchStartX = 0, mTouchStartY = 0, mTouchStartTime = 0, mLongPressTimer = null, mMoved = false;
        row.addEventListener('touchstart', (e) => {
            if (e.touches.length !== 1) return;
            mTouchStartX = e.touches[0].clientX;
            mTouchStartY = e.touches[0].clientY;
            mTouchStartTime = Date.now();
            mMoved = false;

            mLongPressTimer = setTimeout(() => {
                if (!mMoved) {
                    if (navigator.vibrate) navigator.vibrate(28);
                    openContextMenuForTarget(row, mTouchStartX, mTouchStartY);
                }
            }, 420);
        }, { passive: true });

        row.addEventListener('touchmove', (e) => {
            if (e.touches.length !== 1) return;
            const dx = e.touches[0].clientX - mTouchStartX;
            const dy = e.touches[0].clientY - mTouchStartY;
            if (Math.abs(dx) > 10 || Math.abs(dy) > 10) {
                mMoved = true;
                clearTimeout(mLongPressTimer);
            }
            if (Math.abs(dx) > Math.abs(dy) && dx > 15 && dx < 80) {
                const bubble = row.querySelector('.message-bubble');
                if (bubble) bubble.style.transform = `translateX(${dx * 0.35}px)`;
            }
        }, { passive: true });

        row.addEventListener('touchend', (e) => {
            clearTimeout(mLongPressTimer);
            const bubble = row.querySelector('.message-bubble');
            if (bubble) {
                bubble.style.transition = 'transform 0.22s cubic-bezier(0.16, 1, 0.3, 1)';
                bubble.style.transform = '';
                setTimeout(() => { if (bubble) bubble.style.transition = ''; }, 220);
            }
            if (Date.now() - mTouchStartTime < 400 && e.changedTouches.length === 1) {
                const dx = e.changedTouches[0].clientX - mTouchStartX;
                const dy = e.changedTouches[0].clientY - mTouchStartY;
                if (dx > 50 && Math.abs(dy) < 35) {
                    if (navigator.vibrate) navigator.vibrate(20);
                    window.triggerReply(msg.id);
                }
            }
        }, { passive: true });

        elMessagesContainer.appendChild(row);
        if (msg.fromMe || isNearBottom()) {
            scrollToBottom(false);
        } else {
            unreadScrolledCount++;
            updateScrollBottomButton();
        }
    }

    window.toggleCipher = function (id) {
        const box = document.getElementById(`cipher_${id}`);
        if (box) {
            box.style.display = box.style.display === 'none' ? 'block' : 'none';
        }
    };

    function isNearBottom(threshold = 140) {
        if (!elMessagesContainer) return true;
        return (elMessagesContainer.scrollHeight - elMessagesContainer.scrollTop - elMessagesContainer.clientHeight) <= threshold;
    }

    function scrollToBottom(smooth = false) {
        if (!elMessagesContainer) return;
        if (smooth) {
            elMessagesContainer.scrollTo({ top: elMessagesContainer.scrollHeight, behavior: 'smooth' });
        } else {
            elMessagesContainer.scrollTop = elMessagesContainer.scrollHeight;
        }
        unreadScrolledCount = 0;
        updateScrollBottomButton();
    }

    function updateScrollBottomButton() {
        if (!elBtnScrollBottom) return;
        if (isNearBottom(120)) {
            elBtnScrollBottom.style.display = 'none';
            unreadScrolledCount = 0;
            if (elScrollUnreadBadge) elScrollUnreadBadge.style.display = 'none';
        } else {
            elBtnScrollBottom.style.display = 'flex';
            if (elScrollUnreadBadge) {
                if (unreadScrolledCount > 0) {
                    elScrollUnreadBadge.textContent = unreadScrolledCount > 99 ? '99+' : unreadScrolledCount;
                    elScrollUnreadBadge.style.display = 'flex';
                } else {
                    elScrollUnreadBadge.style.display = 'none';
                }
            }
        }
    }

    if (elMessagesContainer) {
        elMessagesContainer.addEventListener('scroll', updateScrollBottomButton, { passive: true });
    }

    if (elBtnScrollBottom) {
        elBtnScrollBottom.addEventListener('click', () => {
            scrollToBottom(true);
        });
    }

    if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', () => {
            if (activeContactId && isNearBottom(200)) {
                setTimeout(() => scrollToBottom(false), 50);
            }
        });
    }

    // ==============================================================================
    // 12. ГОЛОСОВЫЕ СООБЩЕНИЯ (ГС) - УНИВЕРСАЛЬНЫЙ WAV/PCM ДЛЯ ВСЕХ ПЛАТФОРМ
    // ==============================================================================
    function encodeWavBlob(samplesList, sampleRate) {
        let totalSamples = 0;
        for (let i = 0; i < samplesList.length; i++) totalSamples += samplesList[i].length;
        const merged = new Float32Array(totalSamples);
        let offset = 0;
        for (let i = 0; i < samplesList.length; i++) {
            merged.set(samplesList[i], offset);
            offset += samplesList[i].length;
        }

        const buffer = new ArrayBuffer(44 + merged.length * 2);
        const view = new DataView(buffer);

        const writeStr = (off, str) => {
            for (let i = 0; i < str.length; i++) view.setUint8(off + i, str.charCodeAt(i));
        };

        writeStr(0, 'RIFF');
        view.setUint32(4, 36 + merged.length * 2, true);
        writeStr(8, 'WAVE');
        writeStr(12, 'fmt ');
        view.setUint32(16, 16, true);
        view.setUint16(20, 1, true); // PCM
        view.setUint16(22, 1, true); // 1 канал (mono)
        view.setUint32(24, sampleRate, true);
        view.setUint32(28, sampleRate * 2, true);
        view.setUint16(32, 2, true);
        view.setUint16(34, 16, true); // 16-bit
        writeStr(36, 'data');
        view.setUint32(40, merged.length * 2, true);

        let dataOff = 44;
        for (let i = 0; i < merged.length; i++, dataOff += 2) {
            let s = Math.max(-1, Math.min(1, merged[i]));
            view.setInt16(dataOff, s < 0 ? s * 0x8000 : s * 0x7FFF, true);
        }
        return new Blob([view], { type: 'audio/wav' });
    }

    if (elBtnRecordVoice) {
        elBtnRecordVoice.onclick = async () => {
            if ((audioContext && audioContext.state === 'running') || (mediaRecorder && mediaRecorder.state === 'recording')) {
                return;
            }
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                startVoiceRecording(stream);
            } catch (err) {
                alert('Не удалось получить доступ к микрофону: ' + err.message);
            }
        };
    }

    function startVoiceRecording(stream) {
        audioStream = stream;
        audioChunks = [];

        let mimeType = '';
        const candidateTypes = [
            'audio/webm;codecs=opus',
            'audio/webm',
            'audio/ogg;codecs=opus',
            'audio/mp4',
            'audio/aac'
        ];
        if (window.MediaRecorder && MediaRecorder.isTypeSupported) {
            for (const t of candidateTypes) {
                if (MediaRecorder.isTypeSupported(t)) {
                    mimeType = t;
                    break;
                }
            }
        }

        try {
            mediaRecorder = mimeType ? new MediaRecorder(stream, { mimeType }) : new MediaRecorder(stream);
        } catch {
            mediaRecorder = new MediaRecorder(stream);
        }

        mediaRecorder.ondataavailable = (ev) => {
            if (ev.data && ev.data.size > 0) audioChunks.push(ev.data);
        };

        mediaRecorder.start(100);

        // Переключение интерфейса в режим записи
        elChatInputArea.style.display = 'none';
        elVoicePanel.style.display = 'flex';

        voiceRecordingSeconds = 0;
        updateVoiceRecTimer();
        if (voiceRecordingTimer) clearInterval(voiceRecordingTimer);
        voiceRecordingTimer = setInterval(() => {
            voiceRecordingSeconds++;
            updateVoiceRecTimer();
        }, 1000);
    }

    function updateVoiceRecTimer() {
        const mins = Math.floor(voiceRecordingSeconds / 60);
        const secs = voiceRecordingSeconds % 60;
        elVoiceRecTimer.textContent = `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }

    function stopVoiceRecordingStreams() {
        if (mediaRecorder && mediaRecorder.state === 'recording') {
            try { mediaRecorder.stop(); } catch {}
        }
        if (audioStream) {
            audioStream.getTracks().forEach(track => track.stop());
            audioStream = null;
        }
        if (voiceRecordingTimer) {
            clearInterval(voiceRecordingTimer);
            voiceRecordingTimer = null;
        }
        elVoicePanel.style.display = 'none';
        elChatInputArea.style.display = 'block';
    }

    if (elBtnCancelVoice) {
        elBtnCancelVoice.onclick = () => {
            stopVoiceRecordingStreams();
            audioChunks = [];
        };
    }

    if (elBtnSendVoice) {
        elBtnSendVoice.onclick = () => {
            const duration = Math.max(1, voiceRecordingSeconds);
            if (!mediaRecorder || mediaRecorder.state !== 'recording') {
                stopVoiceRecordingStreams();
                return;
            }

            mediaRecorder.onstop = async () => {
                try {
                    const rawBlob = new Blob(audioChunks, { type: mediaRecorder.mimeType || 'audio/webm' });
                    let wavDataUrl = null;

                    // Всегда декодируем запись в 16-битный PCM WAV,
                    // который гарантированно без сторонних кодеков играет на Windows ПК (CIPHER.exe), Android и Web!
                    try {
                        const AudioContextClass = window.AudioContext || window.webkitAudioContext;
                        if (AudioContextClass) {
                            const actx = new AudioContextClass();
                            if (actx.state === 'suspended') await actx.resume();
                            const arrayBuf = await rawBlob.arrayBuffer();
                            const audioBuf = await actx.decodeAudioData(arrayBuf);
                            const channelData = audioBuf.getChannelData(0);
                            const wavBlob = encodeWavBlob([channelData], audioBuf.sampleRate);
                            wavDataUrl = await new Promise((res, rej) => {
                                const r = new FileReader();
                                r.onload = () => res(r.result);
                                r.onerror = rej;
                                r.readAsDataURL(wavBlob);
                            });
                            try { actx.close(); } catch {}
                        }
                    } catch (convErr) {
                        console.warn('[VOICE] PCM decode failed, fallback to raw format:', convErr);
                    }

                    if (!wavDataUrl) {
                        wavDataUrl = await new Promise((res, rej) => {
                            const r = new FileReader();
                            r.onload = () => res(r.result);
                            r.onerror = rej;
                            r.readAsDataURL(rawBlob);
                        });
                    }

                    sendMessage('', {
                        data: wavDataUrl,
                        duration: duration
                    });
                } catch (err) {
                    console.error('[VOICE SEND ERROR]', err);
                } finally {
                    stopVoiceRecordingStreams();
                }
            };

            mediaRecorder.stop();
        };
    }

    function updateVoicePlayBtnUi(msgId, isPlaying) {
        const btn = document.getElementById(`voice_btn_${msgId}`);
        if (!btn) return;
        const playIcon = btn.querySelector('.voice-icon-play');
        const pauseIcon = btn.querySelector('.voice-icon-pause');
        if (playIcon) playIcon.style.display = isPlaying ? 'none' : 'block';
        if (pauseIcon) pauseIcon.style.display = isPlaying ? 'block' : 'none';
    }

    // Воспроизведение голосовых сообщений
    window.playVoiceNote = function (msgId, audioSrc) {
        if (!audioSrc) return;
        if (!audioSrc.startsWith('data:') && !audioSrc.startsWith('http') && !audioSrc.startsWith('blob:')) {
            audioSrc = 'data:audio/wav;base64,' + audioSrc;
        }
        const fill = document.getElementById(`voice_fill_${msgId}`);
        const curTimeEl = document.getElementById(`voice_cur_${msgId}`);

        if (activeAudioPlayer) {
            if (activeAudioPlayer.dataset.msgId === msgId) {
                if (activeAudioPlayer.paused) {
                    activeAudioPlayer.play();
                    updateVoicePlayBtnUi(msgId, true);
                } else {
                    activeAudioPlayer.pause();
                    updateVoicePlayBtnUi(msgId, false);
                }
                return;
            } else {
                activeAudioPlayer.pause();
                updateVoicePlayBtnUi(activeAudioPlayer.dataset.msgId, false);
            }
        }

        const audio = new Audio(audioSrc);
        audio.dataset.msgId = msgId;
        const speedBtn = document.getElementById(`speed_${msgId}`);
        if (speedBtn) {
            const sp = parseFloat(speedBtn.textContent) || 1;
            audio.playbackRate = sp;
        }
        activeAudioPlayer = audio;

        audio.ontimeupdate = () => {
            if (audio.duration) {
                const pct = (audio.currentTime / audio.duration) * 100;
                if (fill) fill.style.width = pct + '%';
                if (curTimeEl) curTimeEl.textContent = formatAudioTime(Math.floor(audio.currentTime));
            }
        };

        audio.onended = () => {
            updateVoicePlayBtnUi(msgId, false);
            if (fill) fill.style.width = '0%';
            if (curTimeEl) curTimeEl.textContent = '0:00';
            activeAudioPlayer = null;
        };

        audio.play().then(() => {
            updateVoicePlayBtnUi(msgId, true);
        }).catch(err => {
            console.error('Ошибка воспроизведения аудио:', err);
            updateVoicePlayBtnUi(msgId, false);
        });
    };

    window.seekVoiceTrack = function (event, msgId) {
        if (!activeAudioPlayer || activeAudioPlayer.dataset.msgId !== msgId || !activeAudioPlayer.duration) return;
        const rect = event.currentTarget.getBoundingClientRect();
        const clickX = event.clientX - rect.left;
        const pct = Math.max(0, Math.min(1, clickX / rect.width));
        activeAudioPlayer.currentTime = pct * activeAudioPlayer.duration;
    };

    function formatAudioTime(seconds) {
        const m = Math.floor(seconds / 60);
        const s = Math.floor(seconds % 60);
        return `${m}:${s.toString().padStart(2, '0')}`;
    }

    // ==============================================================================
    // 13. ПРИКРЕПЛЕНИЕ ФОТО И ФАЙЛОВ, DRAG&DROP, ВСТАВКА ИЗ БУФЕРА (CTRL+V)
    // ==============================================================================
    if (elBtnAttachFile && elFileInput) {
        elBtnAttachFile.onclick = () => elFileInput.click();

        elFileInput.onchange = (e) => {
            const file = e.target.files[0];
            if (file) handleSelectedFile(file);
        };
    }

    function handleSelectedFile(file) {
        if (!file) return;

        // Максимальный размер 20 МБ
        if (file.size > 20 * 1024 * 1024) {
            alert('Максимальный размер вложения для сквозного шифрования: 20 МБ');
            if (elFileInput) elFileInput.value = '';
            return;
        }

        const reader = new FileReader();
        reader.onload = (event) => {
            attachedFile = {
                name: file.name,
                type: file.type || 'application/octet-stream',
                size: file.size,
                data: event.target.result
            };

            elFilePreviewName.textContent = file.name;
            elFilePreviewSize.textContent = formatBytes(file.size);

            if (file.type && file.type.startsWith('image/')) {
                elPreviewImg.src = event.target.result;
                elPreviewImg.style.display = 'block';
                elPreviewFileIcon.style.display = 'none';
            } else {
                elPreviewImg.style.display = 'none';
                elPreviewFileIcon.style.display = 'block';
            }

            elFilePreviewBar.style.display = 'flex';
            updateSendButtonVisibility();
            elMessageInput.focus();
        };
        reader.readAsDataURL(file);
    }

    function clearAttachedFile() {
        attachedFile = null;
        if (elFileInput) elFileInput.value = '';
        if (elFilePreviewBar) elFilePreviewBar.style.display = 'none';
        if (elPreviewImg) elPreviewImg.src = '';
        updateSendButtonVisibility();
    }

    if (elBtnRemoveAttachment) {
        elBtnRemoveAttachment.onclick = clearAttachedFile;
    }

    // Drag and drop файлов прямо в окно чата
    if (elDropZone && elDragOverlay) {
        window.addEventListener('dragenter', (e) => {
            if (activeContactId) {
                e.preventDefault();
                elDragOverlay.style.display = 'flex';
            }
        });

        elDragOverlay.addEventListener('dragover', (e) => {
            e.preventDefault();
        });

        elDragOverlay.addEventListener('dragleave', (e) => {
            e.preventDefault();
            elDragOverlay.style.display = 'none';
        });

        elDragOverlay.addEventListener('drop', (e) => {
            e.preventDefault();
            elDragOverlay.style.display = 'none';
            if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
                handleSelectedFile(e.dataTransfer.files[0]);
            }
        });
    }

    // Вставка скриншота/картинки из буфера обмена (Ctrl + V)
    window.addEventListener('paste', (e) => {
        if (!activeContactId) return;
        const items = (e.clipboardData || e.originalEvent.clipboardData).items;
        for (let item of items) {
            if (item.kind === 'file') {
                const blob = item.getAsFile();
                if (blob) {
                    const filename = blob.name === 'image.png' ? `Скриншот_${new Date().toLocaleTimeString().replace(/:/g, '-')}.png` : blob.name;
                    const namedFile = new File([blob], filename, { type: blob.type });
                    handleSelectedFile(namedFile);
                }
            }
        }
    });

    // ==============================================================================
    // 14. ПОЛНОЭКРАННЫЙ ПРОСМОТР ФОТО (LIGHTBOX)
    // ==============================================================================
    window.openLightbox = function (src, filename) {
        if (elLightboxImg && elModalLightbox) {
            elLightboxImg.src = src;
            if (elLightboxFilename) elLightboxFilename.textContent = filename || 'photo.jpg';
            if (elLightboxDownload) {
                elLightboxDownload.href = src;
                elLightboxDownload.download = filename || 'photo.jpg';
            }
            elModalLightbox.style.display = 'flex';
        }
    };

    const btnCloseLightbox = document.getElementById('btn-close-lightbox');
    if (btnCloseLightbox) {
        btnCloseLightbox.onclick = () => elModalLightbox.style.display = 'none';
    }
    if (elModalLightbox) {
        elModalLightbox.onclick = (e) => {
            if (e.target === elModalLightbox || e.target.classList.contains('lightbox-content')) {
                elModalLightbox.style.display = 'none';
            }
        };
    }

    // ==============================================================================
    // 15. ПОИСК, ГОРЯЧИЕ КЛАВИШИ, ПОЛЕ ВВОДА
    // ==============================================================================
    if (elInputSearchChats) {
        elInputSearchChats.oninput = (e) => {
            currentSearchQuery = e.target.value.trim();
            renderContactList();
        };
    }

    elMessageInput.addEventListener('input', function () {
        this.style.height = 'auto';
        this.style.height = Math.min(this.scrollHeight, 120) + 'px';
        updateSendButtonVisibility();
        notifyTyping();
        if (activeContactId) {
            chatDrafts[activeContactId] = this.value;
            idbSet(STORAGE_KEY_DRAFTS, chatDrafts);
        }
    });

    elMessageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            elMessageForm.dispatchEvent(new Event('submit'));
        }
    });

    elMessageForm.onsubmit = (e) => {
        e.preventDefault();
        const text = elMessageInput.value;
        if (text.trim() || attachedFile) {
            sendMessage(text);
            elMessageInput.value = '';
            elMessageInput.style.height = 'auto';
            updateSendButtonVisibility();
        }
    };

    // Закрытие всех окон по Escape
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeAllModals();
            if (mediaRecorder && mediaRecorder.state === 'recording') {
                elBtnCancelVoice.click();
            }
        }
        if ((e.ctrlKey || e.metaKey) && (e.key === 'f' || e.key === 'а' || e.key === 'F')) {
            e.preventDefault();
            if (elInputSearchChats) elInputSearchChats.focus();
        }
    });

    function closeAllModals() {
        const modals = document.querySelectorAll('.modal-backdrop, .lightbox-overlay');
        modals.forEach(m => m.style.display = 'none');
    }

    // ==============================================================================
    // 16. МОДАЛЬНЫЕ ОКНА: ПРОФИЛЬ, КОНТАКТЫ, СЕРВЕР
    // ==============================================================================
    // Мой профиль
    document.getElementById('btn-my-profile').onclick = () => {
        elModalProfile.style.display = 'flex';
    };
    document.getElementById('btn-close-profile').onclick = () => {
        elModalProfile.style.display = 'none';
    };
    document.getElementById('btn-save-profile').onclick = () => {
        const newName = document.getElementById('input-edit-my-name').value.trim();
        if (newName) {
            identity.name = newName;
            localStorage.setItem(STORAGE_KEY_IDENTITY, JSON.stringify(identity));
            elMyName.textContent = newName;
            elMyAvatar.textContent = newName[0].toUpperCase();
        }
        elModalProfile.style.display = 'none';
    };

    // Экспорт ключей
    const btnExportId = document.getElementById('btn-export-identity');
    if (btnExportId) {
        btnExportId.onclick = () => {
            const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(identity, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute('href', dataStr);
            downloadAnchor.setAttribute('download', `cipher_identity_${identity.name || 'key'}.json`);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        };
    }

    // Импорт ключей
    const btnImportTrigger = document.getElementById('btn-import-identity-trigger');
    const inputImportFile = document.getElementById('import-identity-file');
    if (btnImportTrigger && inputImportFile) {
        btnImportTrigger.onclick = () => inputImportFile.click();

        inputImportFile.onchange = (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = async (event) => {
                try {
                    const parsed = JSON.parse(event.target.result);
                    if (!parsed.publicKeyB64 || !parsed.privateKeyB64 || !parsed.id) {
                        throw new Error('Файл не содержит необходимых ключей');
                    }
                    identity = parsed;
                    localStorage.setItem(STORAGE_KEY_IDENTITY, JSON.stringify(identity));
                    alert('Личность успешно импортирована!');
                    window.location.reload();
                } catch (err) {
                    alert('Ошибка импорта ключей: ' + err.message);
                }
            };
            reader.readAsText(file);
        };
    }

    // Добавление контакта
    document.getElementById('btn-add-contact').onclick = () => {
        elModalAddContact.style.display = 'flex';
        document.getElementById('input-contact-name').focus();
    };
    document.getElementById('btn-close-add-contact').onclick =
    document.getElementById('btn-cancel-add-contact').onclick = () => {
        elModalAddContact.style.display = 'none';
    };

    document.getElementById('btn-confirm-add-contact').onclick = async () => {
        const name = document.getElementById('input-contact-name').value.trim();
        const pubKeyB64 = document.getElementById('input-contact-pubkey').value.trim();

        if (!name || !pubKeyB64) {
            alert('Пожалуйста, заполните имя и открытый ключ.');
            return;
        }

        try {
            const rawPub = WebCryptoE2EE.b642buf(pubKeyB64);
            const hashBuf = await window.crypto.subtle.digest('SHA-256', rawPub);
            const contactId = WebCryptoE2EE.buf2hex(hashBuf);

            if (contactId === identity.id) {
                alert('Нельзя добавить свой собственный ключ в качестве собеседника.');
                return;
            }

            const existing = contacts.find(c => c.id === contactId);
            if (existing) {
                existing.name = name;
                existing.publicKeyB64 = pubKeyB64;
            } else {
                contacts.push({
                    id: contactId,
                    name: name,
                    publicKeyB64: pubKeyB64
                });
            }

            saveContacts();
            elModalAddContact.style.display = 'none';
            document.getElementById('input-contact-name').value = '';
            document.getElementById('input-contact-pubkey').value = '';
            selectContact(contactId);
        } catch (err) {
            alert('Неверный формат открытого ключа: ' + err.message);
        }
    };

    // Карточка контакта
    function openContactInfoModal() {
        if (!activeContactId) return;
        const contact = contacts.find(c => c.id === activeContactId);
        if (!contact) return;

        document.getElementById('contact-info-name').value = contact.name;
        document.getElementById('contact-info-id').value = contact.id;
        document.getElementById('contact-info-pubkey').value = contact.publicKeyB64;
        elModalContactInfo.style.display = 'flex';
    }

    const btnViewKey = document.getElementById('btn-view-contact-key');
    if (btnViewKey) btnViewKey.onclick = openContactInfoModal;

    const activeHeaderInfo = document.getElementById('active-user-header-info');
    if (activeHeaderInfo) activeHeaderInfo.onclick = openContactInfoModal;

    const btnCloseContactInfo = document.getElementById('btn-close-contact-info');
    if (btnCloseContactInfo) btnCloseContactInfo.onclick = () => elModalContactInfo.style.display = 'none';

    const btnSaveContactInfo = document.getElementById('btn-save-contact-info');
    if (btnSaveContactInfo) {
        btnSaveContactInfo.onclick = () => {
            if (!activeContactId) return;
            const contact = contacts.find(c => c.id === activeContactId);
            if (contact) {
                const newName = document.getElementById('contact-info-name').value.trim();
                if (newName) {
                    contact.name = newName;
                    saveContacts();
                    elActiveContactName.textContent = newName;
                }
            }
            elModalContactInfo.style.display = 'none';
        };
    }

    const btnDeleteContact = document.getElementById('btn-delete-contact');
    if (btnDeleteContact) {
        btnDeleteContact.onclick = () => {
            if (!activeContactId) return;
            if (confirm('Удалить этот чат и историю переписки?')) {
                contacts = contacts.filter(c => c.id !== activeContactId);
                delete messages[activeContactId];
                saveContacts();
                saveMessages();
                activeContactId = null;
                elChatHeader.style.display = 'none';
                elChatInputArea.style.display = 'none';
                elEmptyState.style.display = 'block';
                elModalContactInfo.style.display = 'none';
                renderContactList();
            }
        };
    }

    // Настройки сервера
    function openServerModal() {
        const inputWs = document.getElementById('input-server-ws-url');
        const inputSecret = document.getElementById('input-server-secret');
        if (inputWs) inputWs.value = getOptimalWsUrl();
        if (inputSecret) inputSecret.value = localStorage.getItem(STORAGE_KEY_SERVER_SECRET) || '';
        elModalServerSettings.style.display = 'flex';
    }

    document.getElementById('btn-status-badge').onclick = openServerModal;
    document.getElementById('btn-footer-server').onclick = openServerModal;
    document.getElementById('btn-close-server-settings').onclick =
    document.getElementById('btn-cancel-server-settings').onclick = () => {
        elModalServerSettings.style.display = 'none';
    };

    document.getElementById('btn-set-local-ws').onclick = () => {
        const inputWs = document.getElementById('input-server-ws-url');
        if (inputWs) inputWs.value = 'ws://127.0.0.1:8080';
    };

    document.getElementById('btn-set-tunnel-ws').onclick = () => {
        const inputWs = document.getElementById('input-server-ws-url');
        if (inputWs && serverTunnelUrl) {
            inputWs.value = serverTunnelUrl;
        } else {
            alert('Адрес туннеля еще не получен. Подождите пару секунд.');
        }
    };

    const btnSetLan = document.getElementById('btn-set-lan-ws');
    if (btnSetLan) {
        btnSetLan.onclick = () => {
            const inputWs = document.getElementById('input-server-ws-url');
            if (inputWs) inputWs.value = serverLanUrl || 'ws://192.168.0.37:8080';
        };
    }

    document.getElementById('btn-save-server-settings').onclick = () => {
        let newUrl = document.getElementById('input-server-ws-url').value.trim();
        const newSecret = document.getElementById('input-server-secret') ? document.getElementById('input-server-secret').value.trim() : '';
        if (newUrl) {
            if (newUrl.startsWith('http://')) newUrl = newUrl.replace(/^http:\/\//, 'ws://');
            else if (newUrl.startsWith('https://')) newUrl = newUrl.replace(/^https:\/\//, 'wss://');
            else if (!newUrl.startsWith('ws://') && !newUrl.startsWith('wss://')) newUrl = 'wss://' + newUrl;

            localStorage.setItem(STORAGE_KEY_SERVER_URL, newUrl);
            localStorage.setItem(STORAGE_KEY_SERVER_SECRET, newSecret);
            elModalServerSettings.style.display = 'none';
            if (ws) {
                ws.onclose = null;
                ws.close();
            }
            connectWebSocket();
        }
    };

    // Окно 2 (тест со вторым пользователем)
    const btnPartner = document.getElementById('btn-open-partner');
    if (btnPartner) {
        btnPartner.onclick = () => {
            const targetUser = currentUserProfile === 'Алиса' ? 'Боб' : 'Алиса';
            const partnerUrl = `${window.location.origin}${window.location.pathname}?user=${targetUser}`;
            window.open(partnerUrl, '_blank', 'width=540,height=780');
        };
    }

    // Копирование в буфер
    document.querySelectorAll('.btn-copy-chip').forEach(btn => {
        btn.onclick = () => {
            const targetId = btn.getAttribute('data-target');
            const target = document.getElementById(targetId);
            if (target) {
                target.select();
                navigator.clipboard.writeText(target.value);
                const origText = btn.textContent;
                btn.textContent = 'Скопировано!';
                setTimeout(() => btn.textContent = origText, 1500);
            }
        };
    });

    // ==============================================================================
    // 17. ЗВУКОВЫЕ ЭФФЕКТЫ (TELEGRAM STYLE - СИНТЕЗ ЧЕРЕЗ WEB AUDIO API)
    // ==============================================================================
    let audioCtx = null;
    function getAudioContext() {
        if (!audioCtx) {
            const AudioContextClass = window.AudioContext || window.webkitAudioContext;
            if (AudioContextClass) audioCtx = new AudioContextClass();
        }
        if (audioCtx && audioCtx.state === 'suspended') {
            audioCtx.resume();
        }
        return audioCtx;
    }

    function playSendSound() {
        try {
            const ctx = getAudioContext();
            if (!ctx) return;
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sine';
            const now = ctx.currentTime;
            osc.frequency.setValueAtTime(800, now);
            osc.frequency.exponentialRampToValueAtTime(1400, now + 0.05);
            gain.gain.setValueAtTime(0.08, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.05);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.06);
        } catch {}
    }

    function playReceiveSound() {
        try {
            const ctx = getAudioContext();
            if (!ctx) return;
            const now = ctx.currentTime;
            const osc1 = ctx.createOscillator();
            const osc2 = ctx.createOscillator();
            const gain = ctx.createGain();
            osc1.type = 'sine';
            osc2.type = 'sine';
            osc1.frequency.setValueAtTime(587.33, now); // D5
            osc1.frequency.setValueAtTime(880, now + 0.07); // A5
            osc2.frequency.setValueAtTime(1174.66, now + 0.07); // D6
            gain.gain.setValueAtTime(0.12, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.22);
            osc1.connect(gain);
            osc2.connect(gain);
            gain.connect(ctx.destination);
            osc1.start(now);
            osc2.start(now + 0.07);
            osc1.stop(now + 0.24);
            osc2.stop(now + 0.24);
        } catch {}
    }

    // ==============================================================================
    // 18. КАСТОМНОЕ ДЕСКТОПНОЕ МЕНЮ (ПОЛНЫЙ ЗАПРЕТ БРАУЗЕРНОГО МЕНЮ)
    // ==============================================================================
    const elContextMenu = document.getElementById('desktop-context-menu');

    function closeContextMenu() {
        if (elContextMenu) elContextMenu.style.display = 'none';
    }

    window.addEventListener('click', closeContextMenu);
    window.addEventListener('scroll', closeContextMenu, true);

    // Блокировка стандартных браузерных горячих клавиш (F5, Ctrl+R, Ctrl+P, Ctrl+U)
    window.addEventListener('keydown', (e) => {
        if (e.key === 'F5' || 
            (e.ctrlKey && (e.key === 'r' || e.key === 'R' || e.key === 'p' || e.key === 'P' || e.key === 'u' || e.key === 'U'))) {
            e.preventDefault();
        }
        if (e.key === 'Escape') {
            closeContextMenu();
        }
    });

    function openContextMenuForTarget(targetElem, clientX, clientY) {
        if (!elContextMenu || !targetElem) return;

        const messageRow = targetElem.closest('.message-row');
        const imgElem = targetElem.closest('.chat-attachment-img');
        const isInputArea = targetElem.closest('#message-input');
        const contactItem = targetElem.closest('.chat-item');
        const isMobile = window.innerWidth <= 768;

        let menuHtml = '';

        if (imgElem) {
            const src = imgElem.src;
            menuHtml = `
                <div class="context-menu-item" onclick="openLightbox('${src}'); closeContextMenu();">
                    <span class="context-menu-left"><span class="context-menu-icon">🔍</span><span>Открыть фото</span></span>
                </div>
                <div class="context-menu-item" onclick="downloadImageDirect('${src}'); closeContextMenu();">
                    <span class="context-menu-left"><span class="context-menu-icon">💾</span><span>${isMobile ? 'Сохранить фото' : 'Сохранить на ПК'}</span></span>
                </div>
            `;
        } else if (messageRow) {
            const msgId = messageRow.id.replace('msg_el_', '');
            const textElem = messageRow.querySelector('.message-text');
            const textContent = textElem ? textElem.textContent : '';
            const isMyMsg = messageRow.classList.contains('me');

            let editItem = '';
            if (isMyMsg && textContent) {
                editItem = `
                    <div class="context-menu-item" onclick="startEditMessage('${msgId}'); closeContextMenu();">
                        <span class="context-menu-left"><span class="context-menu-icon">✏️</span><span>Редактировать</span></span>
                    </div>
                `;
            }

            const isPinned = pinnedMessages[activeContactId] === msgId;
            const pinItem = `
                <div class="context-menu-item" onclick="${isPinned ? `unpinMessage('${activeContactId}')` : `pinMessage('${msgId}')`}; closeContextMenu();">
                    <span class="context-menu-left"><span class="context-menu-icon">📌</span><span>${isPinned ? 'Открепить' : 'Закрепить'}</span></span>
                </div>
            `;

            const forwardItem = `
                <div class="context-menu-item" onclick="openForwardModal('${msgId}'); closeContextMenu();">
                    <span class="context-menu-left"><span class="context-menu-icon">➡️</span><span>Переслать</span></span>
                </div>
            `;

            menuHtml = `
                <div class="context-reactions-row">
                    <span onclick="toggleReaction('${msgId}', '👍'); closeContextMenu();">👍</span>
                    <span onclick="toggleReaction('${msgId}', '❤️'); closeContextMenu();">❤️</span>
                    <span onclick="toggleReaction('${msgId}', '🔥'); closeContextMenu();">🔥</span>
                    <span onclick="toggleReaction('${msgId}', '👏'); closeContextMenu();">👏</span>
                    <span onclick="toggleReaction('${msgId}', '😂'); closeContextMenu();">😂</span>
                    <span onclick="toggleReaction('${msgId}', '😮'); closeContextMenu();">😮</span>
                </div>
                <div class="context-menu-item" onclick="window.triggerReply('${msgId}'); closeContextMenu();">
                    <span class="context-menu-left"><span class="context-menu-icon">↩</span><span>Ответить</span></span>
                </div>
                ${pinItem}
                ${forwardItem}
                ${editItem}
                <div class="context-menu-item" onclick="copyStringToClipboard('${escapeJsArg(textContent)}'); closeContextMenu();">
                    <span class="context-menu-left"><span class="context-menu-icon">📋</span><span>Копировать текст</span></span>
                    <span class="context-menu-shortcut">Ctrl+C</span>
                </div>
                <div class="context-menu-item" onclick="toggleCipher('${msgId}'); closeContextMenu();">
                    <span class="context-menu-left"><span class="context-menu-icon">🔐</span><span>Показать E2EE конверт</span></span>
                </div>
                <div class="context-menu-divider"></div>
                <div class="context-menu-item danger" onclick="deleteMessageForEveryone('${msgId}'); closeContextMenu();">
                    <span class="context-menu-left"><span class="context-menu-icon">💥</span><span>Удалить у всех</span></span>
                </div>
                <div class="context-menu-item danger" onclick="deleteMessageById('${msgId}'); closeContextMenu();">
                    <span class="context-menu-left"><span class="context-menu-icon">🗑️</span><span>Удалить у себя</span></span>
                </div>
            `;
        } else if (isInputArea) {
            menuHtml = `
                <div class="context-menu-item" onclick="pasteClipboardToInput(); closeContextMenu();">
                    <span class="context-menu-left"><span class="context-menu-icon">📋</span><span>Вставить</span></span>
                    <span class="context-menu-shortcut">Ctrl+V</span>
                </div>
                <div class="context-menu-item" onclick="document.getElementById('message-input').select(); closeContextMenu();">
                    <span class="context-menu-left"><span class="context-menu-icon">🔲</span><span>Выделить всё</span></span>
                    <span class="context-menu-shortcut">Ctrl+A</span>
                </div>
            `;
        } else if (contactItem) {
            menuHtml = `
                <div class="context-menu-item" onclick="openContactInfoModal(); closeContextMenu();">
                    <span class="context-menu-left"><span class="context-menu-icon">👤</span><span>Профиль контакта</span></span>
                </div>
                <div class="context-menu-item" onclick="clearChatHistory(activeContactId || ''); closeContextMenu();">
                    <span class="context-menu-left"><span class="context-menu-icon">🧹</span><span>Очистить историю</span></span>
                </div>
                <div class="context-menu-divider"></div>
                <div class="context-menu-item danger" onclick="document.getElementById('btn-delete-contact').click(); closeContextMenu();">
                    <span class="context-menu-left"><span class="context-menu-icon">🗑️</span><span>Удалить чат</span></span>
                </div>
            `;
        } else {
            closeContextMenu();
            return;
        }

        if (isMobile) {
            menuHtml += `
                <div class="context-menu-item context-cancel-item" onclick="closeContextMenu();">
                    <span>✕ Отмена</span>
                </div>
            `;
        }

        elContextMenu.innerHTML = menuHtml;
        elContextMenu.style.display = 'flex';

        if (isMobile) {
            elContextMenu.classList.add('mobile-action-sheet');
            elContextMenu.style.left = '0px';
            elContextMenu.style.bottom = '0px';
            elContextMenu.style.top = 'auto';
            elContextMenu.style.width = '100%';
        } else {
            elContextMenu.classList.remove('mobile-action-sheet');
            const menuWidth = 220;
            const menuHeight = elContextMenu.offsetHeight || 160;
            const posX = (clientX + menuWidth > window.innerWidth) ? (window.innerWidth - menuWidth - 10) : clientX;
            const posY = (clientY + menuHeight > window.innerHeight) ? (window.innerHeight - menuHeight - 10) : clientY;
            elContextMenu.style.left = `${Math.max(10, posX)}px`;
            elContextMenu.style.top = `${Math.max(10, posY)}px`;
            elContextMenu.style.bottom = 'auto';
            elContextMenu.style.width = 'auto';
        }
    }

    window.addEventListener('contextmenu', (e) => {
        e.preventDefault(); // Полностью глушим стандартный браузерный ПКМ
        openContextMenuForTarget(e.target, e.clientX, e.clientY);
    });

    window.copyStringToClipboard = function (text) {
        if (text) {
            navigator.clipboard.writeText(text);
        }
    };

    window.downloadImageDirect = function (src) {
        const a = document.createElement('a');
        a.href = src;
        a.download = `photo_${Date.now()}.png`;
        document.body.appendChild(a);
        a.click();
        a.remove();
    };

    window.pasteClipboardToInput = async function () {
        try {
            const text = await navigator.clipboard.readText();
            if (text) {
                elMessageInput.value += text;
                elMessageInput.focus();
            }
        } catch {}
    };

    window.deleteMessageById = function (msgId) {
        if (!activeContactId || !messages[activeContactId]) return;
        messages[activeContactId] = messages[activeContactId].filter(m => m.id !== msgId);
        saveMessages();
        const el = document.getElementById(`msg_el_${msgId}`);
        if (el) {
            el.style.transition = 'all 0.25s';
            el.style.opacity = '0';
            el.style.transform = 'scale(0.85)';
            setTimeout(() => el.remove(), 250);
        }
        renderContactList();
    };

    // ==============================================================================
    // 18. УВЕДОМЛЕНИЯ, РЕДАКТИРОВАНИЕ, ГРУППЫ И E2EE ЗВОНКИ (WEBRTC)
    // ==============================================================================

    function triggerMessageNotification(title, body) {
        try {
            if ('vibrate' in navigator) navigator.vibrate([200, 100, 200]);
        } catch (e) {}

        if ('Notification' in window && Notification.permission === 'granted') {
            try {
                if (navigator.serviceWorker && navigator.serviceWorker.controller) {
                    navigator.serviceWorker.ready.then(reg => {
                        reg.showNotification(title || 'Новое сообщение', {
                            body: body || 'Зашифрованное E2EE вложение',
                            icon: 'icon-192.png',
                            badge: 'icon-192.png',
                            vibrate: [200, 100, 200],
                            tag: 'msg_' + Date.now(),
                            renotify: true
                        });
                    });
                } else {
                    new Notification(title || 'Новое сообщение', {
                        body: body || 'Зашифрованное E2EE вложение',
                        icon: 'icon-192.png'
                    });
                }
            } catch (e) {}
        }
    }

    if ('Notification' in window && Notification.permission === 'default') {
        window.addEventListener('click', () => {
            try { Notification.requestPermission(); } catch (e) {}
        }, { once: true });
    }

    window.startEditMessage = function(msgId) {
        if (!activeContactId || !messages[activeContactId]) return;
        const msg = messages[activeContactId].find(m => m.id === msgId);
        if (!msg || !msg.fromMe || !msg.text) return;
        editingMessageId = msgId;
        const editBar = document.getElementById('edit-preview-bar');
        const editText = document.getElementById('edit-preview-text');
        if (editBar && editText) {
            editText.textContent = msg.text;
            editBar.style.display = 'flex';
        }
        elMessageInput.value = msg.text;
        elMessageInput.focus();
    };

    function cancelEditMessage() {
        editingMessageId = null;
        const editBar = document.getElementById('edit-preview-bar');
        if (editBar) editBar.style.display = 'none';
        elMessageInput.value = '';
    }
    document.getElementById('btn-cancel-edit')?.addEventListener('click', cancelEditMessage);

    window.deleteMessageForEveryone = async function(msgId) {
        if (!activeContactId || !messages[activeContactId]) return;
        const contact = contacts.find(c => c.id === activeContactId);
        if (contact) {
            if (contact.isGroup) {
                for (const memberId of contact.memberIds) {
                    if (memberId === identity.id) continue;
                    const memContact = contacts.find(c => c.id === memberId);
                    if (!memContact || !memContact.publicKeyB64) continue;
                    const delPayload = {
                        type: 'delete_message',
                        targetMessageId: msgId,
                        groupId: contact.id,
                        senderId: identity.id,
                        senderPublicKeyB64: identity.publicKeyB64,
                        timestamp: Date.now()
                    };
                    const envelope = await WebCryptoE2EE.encryptMessage(memContact.publicKeyB64, delPayload);
                    ws.send(JSON.stringify({
                        action: 'send_envelope',
                        to: memberId,
                        envelope: envelope
                    }));
                }
            } else {
                const delPayload = {
                    type: 'delete_message',
                    targetMessageId: msgId,
                    senderId: identity.id,
                    senderPublicKeyB64: identity.publicKeyB64,
                    timestamp: Date.now()
                };
                const envelope = await WebCryptoE2EE.encryptMessage(contact.publicKeyB64, delPayload);
                ws.send(JSON.stringify({
                    action: 'send_envelope',
                    to: contact.id,
                    envelope: envelope
                }));
            }
        }
        window.deleteMessageById(msgId);
    };

    // Групповые чаты
    const btnCreateGroup = document.getElementById('btn-create-group');
    const modalCreateGroup = document.getElementById('modal-create-group');
    const btnCloseCreateGroup = document.getElementById('btn-close-create-group');
    const btnCancelCreateGroup = document.getElementById('btn-cancel-create-group');
    const btnConfirmCreateGroup = document.getElementById('btn-confirm-create-group');
    const groupContactsList = document.getElementById('group-contacts-list');
    const inputGroupName = document.getElementById('input-group-name');

    if (btnCreateGroup && modalCreateGroup) {
        btnCreateGroup.onclick = () => {
            if (!groupContactsList) return;
            groupContactsList.innerHTML = '';
            const normalContacts = contacts.filter(c => !c.isGroup);
            if (normalContacts.length === 0) {
                groupContactsList.innerHTML = '<div style="color:var(--text-dim);padding:8px;">Сначала добавьте хотя бы одного собеседника.</div>';
            } else {
                normalContacts.forEach(c => {
                    const label = document.createElement('label');
                    label.className = 'group-member-item';
                    label.innerHTML = `
                        <input type="checkbox" value="${c.id}">
                        <span style="font-weight:600;">${escapeHtml(c.name)}</span>
                        <span style="font-size:11px;color:var(--text-dim);">(${c.id.slice(0, 8)}...)</span>
                    `;
                    groupContactsList.appendChild(label);
                });
            }
            inputGroupName.value = '';
            modalCreateGroup.style.display = 'flex';
        };

        const closeGrpModal = () => { modalCreateGroup.style.display = 'none'; };
        if (btnCloseCreateGroup) btnCloseCreateGroup.onclick = closeGrpModal;
        if (btnCancelCreateGroup) btnCancelCreateGroup.onclick = closeGrpModal;

        if (btnConfirmCreateGroup) {
            btnConfirmCreateGroup.onclick = () => {
                const name = inputGroupName.value.trim();
                if (!name) {
                    alert('Укажите название группы!');
                    return;
                }
                const checkedIds = Array.from(groupContactsList.querySelectorAll('input[type="checkbox"]:checked')).map(cb => cb.value);
                if (checkedIds.length === 0) {
                    alert('Выберите хотя бы одного участника группы!');
                    return;
                }
                checkedIds.push(identity.id);
                const grpId = 'group_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
                const newGroup = {
                    id: grpId,
                    name: name,
                    isGroup: true,
                    memberIds: checkedIds
                };
                contacts.push(newGroup);
                saveContacts();
                renderContactList();
                closeGrpModal();
                selectContact(grpId);
            };
        }
    }

    // WebRTC E2EE Аудиозвонки
    let peerConnection = null;
    let localStream = null;
    let callToneGen = null;
    let callTimer = null;
    let callSeconds = 0;
    let currentCallPeerId = null;
    let pendingOffer = null;

    const callOverlay = document.getElementById('call-overlay');
    const callAvatar = document.getElementById('call-avatar');
    const callName = document.getElementById('call-name');
    const callStatus = document.getElementById('call-status');
    const callTimerEl = document.getElementById('call-timer');
    const btnCallAccept = document.getElementById('btn-call-accept');
    const btnCallMute = document.getElementById('btn-call-mute');
    const btnCallHangup = document.getElementById('btn-call-hangup');
    const remoteAudioEl = document.getElementById('remote-call-audio');

    function createCallTone(isRing) {
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.frequency.value = isRing ? 440 : 425;
            gain.gain.value = 0.05;
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start();
            return {
                stop: () => {
                    try { osc.stop(); ctx.close(); } catch(e){}
                }
            };
        } catch(e) {
            return { stop: () => {} };
        }
    }

    async function startAudioCall(peerId) {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            alert('Нет подключения к серверу для звонка.');
            return;
        }
        const peerContact = contacts.find(c => c.id === peerId);
        if (!peerContact) return;

        currentCallPeerId = peerId;
        if (callAvatar) {
            callAvatar.textContent = peerContact.name[0].toUpperCase();
            callAvatar.style.background = getColorFromHash(peerId);
        }
        if (callName) callName.textContent = peerContact.name;
        if (callStatus) callStatus.textContent = 'Исходящий E2EE звонок...';
        if (btnCallAccept) btnCallAccept.style.display = 'none';
        if (btnCallMute) btnCallMute.style.display = 'inline-flex';
        if (callTimerEl) callTimerEl.style.display = 'none';
        if (callOverlay) callOverlay.style.display = 'flex';

        callToneGen = createCallTone(false);

        try {
            localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
            peerConnection = new RTCPeerConnection({
                iceServers: [
                    { urls: 'stun:stun.l.google.com:19302' },
                    { urls: 'stun:stun1.l.google.com:19302' }
                ]
            });

            localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));

            peerConnection.ontrack = (event) => {
                if (remoteAudioEl && event.streams[0]) {
                    remoteAudioEl.srcObject = event.streams[0];
                }
            };

            peerConnection.onicecandidate = (event) => {
                if (event.candidate) {
                    ws.send(JSON.stringify({
                        action: 'call_signal',
                        to: peerId,
                        signal: { type: 'candidate', candidate: event.candidate }
                    }));
                }
            };

            const offer = await peerConnection.createOffer();
            await peerConnection.setLocalDescription(offer);

            ws.send(JSON.stringify({
                action: 'call_signal',
                to: peerId,
                signal: { type: 'offer', sdp: offer }
            }));
        } catch (err) {
            console.error('Call error:', err);
            hangupCall();
            alert('Не удалось получить доступ к микрофону: ' + err.message);
        }
    }

    async function handleCallSignal(fromId, signal) {
        if (signal.type === 'offer') {
            currentCallPeerId = fromId;
            pendingOffer = signal.sdp;
            const sender = contacts.find(c => c.id === fromId);
            const sName = sender ? sender.name : `Собеседник (${fromId.slice(0, 6)})`;
            if (callAvatar) {
                callAvatar.textContent = sName[0].toUpperCase();
                callAvatar.style.background = getColorFromHash(fromId);
            }
            if (callName) callName.textContent = sName;
            if (callStatus) callStatus.textContent = 'Входящий E2EE звонок...';
            if (btnCallAccept) btnCallAccept.style.display = 'inline-flex';
            if (btnCallMute) btnCallMute.style.display = 'none';
            if (callTimerEl) callTimerEl.style.display = 'none';
            if (callOverlay) callOverlay.style.display = 'flex';

            callToneGen = createCallTone(true);
            triggerMessageNotification(`Входящий звонок: ${sName}`, 'Нажмите для ответа');
        } else if (signal.type === 'answer') {
            if (callToneGen) { callToneGen.stop(); callToneGen = null; }
            if (peerConnection) {
                await peerConnection.setRemoteDescription(new RTCSessionDescription(signal.sdp));
                startCallTimer();
            }
        } else if (signal.type === 'candidate') {
            if (peerConnection && signal.candidate) {
                try {
                    await peerConnection.addIceCandidate(new RTCIceCandidate(signal.candidate));
                } catch (e) {}
            }
        } else if (signal.type === 'hangup') {
            cleanupCallUI();
        }
    }

    async function acceptCall() {
        if (callToneGen) { callToneGen.stop(); callToneGen = null; }
        if (!pendingOffer || !currentCallPeerId) return;

        if (btnCallAccept) btnCallAccept.style.display = 'none';
        if (btnCallMute) btnCallMute.style.display = 'inline-flex';
        if (callStatus) callStatus.textContent = 'Соединение установлено • E2EE DTLS/SRTP';

        try {
            localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
            peerConnection = new RTCPeerConnection({
                iceServers: [
                    { urls: 'stun:stun.l.google.com:19302' },
                    { urls: 'stun:stun1.l.google.com:19302' }
                ]
            });

            localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));

            peerConnection.ontrack = (event) => {
                if (remoteAudioEl && event.streams[0]) {
                    remoteAudioEl.srcObject = event.streams[0];
                }
            };

            peerConnection.onicecandidate = (event) => {
                if (event.candidate) {
                    ws.send(JSON.stringify({
                        action: 'call_signal',
                        to: currentCallPeerId,
                        signal: { type: 'candidate', candidate: event.candidate }
                    }));
                }
            };

            await peerConnection.setRemoteDescription(new RTCSessionDescription(pendingOffer));
            const answer = await peerConnection.createAnswer();
            await peerConnection.setLocalDescription(answer);

            ws.send(JSON.stringify({
                action: 'call_signal',
                to: currentCallPeerId,
                signal: { type: 'answer', sdp: answer }
            }));

            startCallTimer();
        } catch (err) {
            console.error('Accept error:', err);
            hangupCall();
        }
    }

    function hangupCall() {
        if (currentCallPeerId && ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                action: 'call_signal',
                to: currentCallPeerId,
                signal: { type: 'hangup' }
            }));
        }
        cleanupCallUI();
    }

    function cleanupCallUI() {
        if (callToneGen) { callToneGen.stop(); callToneGen = null; }
        if (callTimer) { clearInterval(callTimer); callTimer = null; }
        if (peerConnection) {
            peerConnection.close();
            peerConnection = null;
        }
        if (localStream) {
            localStream.getTracks().forEach(t => t.stop());
            localStream = null;
        }
        currentCallPeerId = null;
        pendingOffer = null;
        if (callOverlay) callOverlay.style.display = 'none';
    }

    function startCallTimer() {
        callSeconds = 0;
        if (callStatus) callStatus.textContent = 'Звонок активен • E2EE SRTP';
        if (callTimerEl) {
            callTimerEl.textContent = '00:00';
            callTimerEl.style.display = 'block';
        }
        callTimer = setInterval(() => {
            callSeconds++;
            const m = Math.floor(callSeconds / 60);
            const s = callSeconds % 60;
            if (callTimerEl) {
                callTimerEl.textContent = `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
            }
        }, 1000);
    }

    document.getElementById('btn-audio-call')?.addEventListener('click', () => {
        if (activeContactId) startAudioCall(activeContactId);
    });
    document.getElementById('btn-call-accept')?.addEventListener('click', acceptCall);
    document.getElementById('btn-call-hangup')?.addEventListener('click', hangupCall);
    document.getElementById('btn-call-mute')?.addEventListener('click', () => {
        if (localStream) {
            const audioTrack = localStream.getAudioTracks()[0];
            if (audioTrack) {
                audioTrack.enabled = !audioTrack.enabled;
                const btnMute = document.getElementById('btn-call-mute');
                if (btnMute) btnMute.style.opacity = audioTrack.enabled ? '1' : '0.5';
            }
        }
    });

    window.hangupCall = hangupCall;

    // ==============================================================================
    // 19. РЕАКЦИИ И СКОРОСТЬ ГОЛОСОВЫХ СООБЩЕНИЙ (TELEGRAM STYLE)
    // ==============================================================================
    function renderReactionsHtml(reactions, msgId) {
        if (!reactions) return '';
        const emojis = Object.keys(reactions);
        if (emojis.length === 0) return '';
        return emojis.map(emoji => {
            const users = reactions[emoji] || [];
            if (!Array.isArray(users) || users.length === 0) return '';
            const isMy = users.includes(identity ? identity.id : '');
            return `<span class="reaction-chip ${isMy ? 'my-reaction' : ''}" onclick="window.toggleReaction('${msgId}', '${emoji}')">${emoji} <span class="reaction-count">${users.length}</span></span>`;
        }).join('');
    }

    window.toggleReaction = async function(msgId, emoji) {
        if (!activeContactId || !messages[activeContactId] || !identity) return;
        const msg = messages[activeContactId].find(m => m.id === msgId);
        if (!msg) return;

        if (!msg.reactions) msg.reactions = {};
        if (!Array.isArray(msg.reactions[emoji])) msg.reactions[emoji] = [];

        const myId = identity.id;
        const idx = msg.reactions[emoji].indexOf(myId);
        if (idx >= 0) {
            msg.reactions[emoji].splice(idx, 1);
            if (msg.reactions[emoji].length === 0) {
                delete msg.reactions[emoji];
            }
        } else {
            msg.reactions[emoji].push(myId);
        }

        saveMessages();
        const rBox = document.getElementById(`reactions_${msgId}`);
        if (rBox) rBox.innerHTML = renderReactionsHtml(msg.reactions, msgId);

        // Отправка реакции собеседнику / группе
        const contact = contacts.find(c => c.id === activeContactId);
        if (!contact) return;

        const reactionPayload = {
            type: 'reaction',
            targetMessageId: msgId,
            emoji: emoji,
            senderId: myId,
            senderPublicKeyB64: identity.publicKeyB64,
            timestamp: Date.now()
        };

        if (contact.isGroup) {
            for (const memberId of (contact.memberIds || [])) {
                if (memberId === myId) continue;
                const memContact = contacts.find(c => c.id === memberId);
                if (!memContact || !memContact.publicKeyB64) continue;
                try {
                    const env = await WebCryptoE2EE.encryptMessage(memContact.publicKeyB64, reactionPayload);
                    ws.send(JSON.stringify({ action: 'send_envelope', to: memberId, envelope: env }));
                } catch (e) {
                    console.error('Failed to send reaction to group member', e);
                }
            }
        } else if (contact.publicKeyB64) {
            try {
                const env = await WebCryptoE2EE.encryptMessage(contact.publicKeyB64, reactionPayload);
                ws.send(JSON.stringify({ action: 'send_envelope', to: contact.id, envelope: env }));
            } catch (e) {
                console.error('Failed to send reaction', e);
            }
        }
    };

    window.cycleVoiceSpeed = function (msgId, event) {
        if (event) event.stopPropagation();
        const speeds = [1, 1.5, 2];
        const speedBtn = document.getElementById(`speed_${msgId}`);
        const currentSpeed = parseFloat(speedBtn ? speedBtn.textContent : '1') || 1;
        const nextIndex = (speeds.indexOf(currentSpeed) + 1) % speeds.length;
        const nextSpeed = speeds[nextIndex];
        if (speedBtn) speedBtn.textContent = nextSpeed + 'x';
        if (activeAudioPlayer && activeAudioPlayer.dataset.msgId === msgId) {
            activeAudioPlayer.playbackRate = nextSpeed;
        }
    };

    // ==============================================================================
    // 20. ЗАКРЕПЛЕННЫЕ СООБЩЕНИЯ (TELEGRAM STYLE)
    // ==============================================================================
    function updatePinnedBanner(contactId) {
        if (!elPinnedBar) return;
        const pinnedMsgId = pinnedMessages[contactId];
        if (!pinnedMsgId || !messages[contactId]) {
            elPinnedBar.style.display = 'none';
            return;
        }
        const msg = messages[contactId].find(m => m.id === pinnedMsgId);
        if (!msg) {
            elPinnedBar.style.display = 'none';
            return;
        }
        if (elPinnedSnippet) {
            elPinnedSnippet.textContent = msg.text || (msg.file ? `[Вложение: ${msg.file.name || 'файл'}]` : (msg.voice ? '[Голосовое сообщение]' : 'Сообщение'));
        }
        const contentEl = document.getElementById('pinned-content');
        if (contentEl) {
            contentEl.onclick = () => window.jumpToMessage(pinnedMsgId);
        }
        if (elBtnUnpinMessage) {
            elBtnUnpinMessage.onclick = (e) => {
                e.stopPropagation();
                window.unpinMessage(contactId);
            };
        }
        elPinnedBar.style.display = 'flex';
    }

    window.pinMessage = async function(msgId) {
        if (!activeContactId || !identity) return;
        pinnedMessages[activeContactId] = msgId;
        await idbSet(STORAGE_KEY_PINNED, pinnedMessages);
        updatePinnedBanner(activeContactId);

        const contact = contacts.find(c => c.id === activeContactId);
        if (!contact) return;
        const pinPayload = {
            type: 'pin_message',
            targetMessageId: msgId,
            senderId: identity.id,
            timestamp: Date.now()
        };

        if (contact.isGroup) {
            for (const memberId of (contact.memberIds || [])) {
                if (memberId === identity.id) continue;
                const mem = contacts.find(c => c.id === memberId);
                if (!mem || !mem.publicKeyB64) continue;
                try {
                    const env = await WebCryptoE2EE.encryptMessage(mem.publicKeyB64, pinPayload);
                    ws.send(JSON.stringify({ action: 'send_envelope', to: memberId, envelope: env }));
                } catch {}
            }
        } else if (contact.publicKeyB64) {
            try {
                const env = await WebCryptoE2EE.encryptMessage(contact.publicKeyB64, pinPayload);
                ws.send(JSON.stringify({ action: 'send_envelope', to: contact.id, envelope: env }));
            } catch {}
        }
    };

    window.unpinMessage = async function(contactId) {
        if (!contactId || !identity) return;
        delete pinnedMessages[contactId];
        await idbSet(STORAGE_KEY_PINNED, pinnedMessages);
        updatePinnedBanner(contactId);

        const contact = contacts.find(c => c.id === contactId);
        if (!contact) return;
        const unpinPayload = {
            type: 'pin_message',
            unpin: true,
            senderId: identity.id,
            timestamp: Date.now()
        };

        if (contact.isGroup) {
            for (const memberId of (contact.memberIds || [])) {
                if (memberId === identity.id) continue;
                const mem = contacts.find(c => c.id === memberId);
                if (!mem || !mem.publicKeyB64) continue;
                try {
                    const env = await WebCryptoE2EE.encryptMessage(mem.publicKeyB64, unpinPayload);
                    ws.send(JSON.stringify({ action: 'send_envelope', to: memberId, envelope: env }));
                } catch {}
            }
        } else if (contact.publicKeyB64) {
            try {
                const env = await WebCryptoE2EE.encryptMessage(contact.publicKeyB64, unpinPayload);
                ws.send(JSON.stringify({ action: 'send_envelope', to: contact.id, envelope: env }));
            } catch {}
        }
    };

    // ==============================================================================
    // 21. ПОИСК СООБЩЕНИЙ В АКТИВНОМ ЧАТЕ (TELEGRAM STYLE)
    // ==============================================================================
    let inChatSearchResults = [];
    let currentInChatSearchIndex = -1;

    function openInChatSearch() {
        if (elInChatSearchBar) elInChatSearchBar.style.display = 'flex';
        if (elInputInChatSearch) {
            elInputInChatSearch.value = '';
            elInputInChatSearch.focus();
        }
        performInChatSearch('');
    }

    function closeInChatSearch() {
        if (elInChatSearchBar) elInChatSearchBar.style.display = 'none';
        inChatSearchResults = [];
        currentInChatSearchIndex = -1;
        document.querySelectorAll('.search-highlight').forEach(el => {
            el.classList.remove('search-highlight', 'current');
        });
    }

    function performInChatSearch(query) {
        inChatSearchResults = [];
        currentInChatSearchIndex = -1;
        document.querySelectorAll('.search-highlight').forEach(el => {
            el.classList.remove('search-highlight', 'current');
        });

        const cleanQuery = (query || '').trim().toLowerCase();
        if (!cleanQuery || !activeContactId || !messages[activeContactId]) {
            if (elInChatSearchCount) elInChatSearchCount.textContent = '0 совпадений';
            return;
        }

        const msgList = messages[activeContactId];
        msgList.forEach(m => {
            if (m.text && m.text.toLowerCase().includes(cleanQuery)) {
                inChatSearchResults.push(m.id);
            }
        });

        if (elInChatSearchCount) {
            elInChatSearchCount.textContent = `${inChatSearchResults.length} ${inChatSearchResults.length === 1 ? 'совпадение' : (inChatSearchResults.length < 5 ? 'совпадения' : 'совпадений')}`;
        }

        if (inChatSearchResults.length > 0) {
            navigateInChatSearch(0);
        }
    }

    function navigateInChatSearch(direction) {
        if (inChatSearchResults.length === 0) return;
        if (typeof direction === 'number') {
            currentInChatSearchIndex = direction;
        } else if (direction === 'prev') {
            currentInChatSearchIndex = (currentInChatSearchIndex - 1 + inChatSearchResults.length) % inChatSearchResults.length;
        } else if (direction === 'next') {
            currentInChatSearchIndex = (currentInChatSearchIndex + 1) % inChatSearchResults.length;
        }

        const targetId = inChatSearchResults[currentInChatSearchIndex];
        if (elInChatSearchCount) {
            elInChatSearchCount.textContent = `${currentInChatSearchIndex + 1} из ${inChatSearchResults.length}`;
        }

        window.jumpToMessage(targetId);
        const row = document.getElementById(`msg_el_${targetId}`);
        if (row) {
            const textEl = row.querySelector('.message-text');
            if (textEl) {
                document.querySelectorAll('.search-highlight.current').forEach(e => e.classList.remove('current'));
                textEl.classList.add('search-highlight', 'current');
            }
        }
    }

    if (elBtnSearchInChat) elBtnSearchInChat.addEventListener('click', openInChatSearch);
    if (elBtnInChatClose) elBtnInChatClose.addEventListener('click', closeInChatSearch);
    if (elBtnInChatPrev) elBtnInChatPrev.addEventListener('click', () => navigateInChatSearch('prev'));
    if (elBtnInChatNext) elBtnInChatNext.addEventListener('click', () => navigateInChatSearch('next'));
    if (elInputInChatSearch) {
        elInputInChatSearch.addEventListener('input', (e) => performInChatSearch(e.target.value));
        elInputInChatSearch.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                navigateInChatSearch(e.shiftKey ? 'prev' : 'next');
            } else if (e.key === 'Escape') {
                closeInChatSearch();
            }
        });
    }

    // ==============================================================================
    // 22. ПЕРЕСЫЛКА СООБЩЕНИЙ (TELEGRAM STYLE)
    // ==============================================================================
    let pendingForwardMsgId = null;

    window.openForwardModal = function(msgId) {
        if (!activeContactId || !messages[activeContactId]) return;
        const msg = messages[activeContactId].find(m => m.id === msgId);
        if (!msg) return;

        pendingForwardMsgId = msgId;
        if (!elModalForward || !elForwardPreview || !elForwardContactList) return;

        elForwardPreview.textContent = msg.text || (msg.file ? `[Файл: ${msg.file.name}]` : (msg.voice ? '[Голосовое сообщение]' : 'Вложение'));
        elForwardContactList.innerHTML = '';

        contacts.forEach(c => {
            const row = document.createElement('div');
            row.className = 'forward-contact-row';
            row.innerHTML = `
                <div class="avatar" style="width: 32px; height: 32px; font-size: 14px; background: ${getColorFromHash(c.id)};">${escapeHtml(c.name[0].toUpperCase())}</div>
                <div style="font-weight: 500;">${escapeHtml(c.name)}</div>
            `;
            row.onclick = () => {
                forwardMessageTo(c.id);
                closeForwardModal();
            };
            elForwardContactList.appendChild(row);
        });

        elModalForward.style.display = 'flex';
    };

    function closeForwardModal() {
        if (elModalForward) elModalForward.style.display = 'none';
        pendingForwardMsgId = null;
    }

    if (elBtnCloseForward) elBtnCloseForward.addEventListener('click', closeForwardModal);
    if (elBtnCancelForward) elBtnCancelForward.addEventListener('click', closeForwardModal);

    async function forwardMessageTo(targetContactId) {
        if (!pendingForwardMsgId || !activeContactId || !messages[activeContactId]) return;
        const origMsg = messages[activeContactId].find(m => m.id === pendingForwardMsgId);
        if (!origMsg) return;

        const originalSender = origMsg.fromMe ? 'Вы' : (contacts.find(c => c.id === activeContactId)?.name || 'Собеседник');
        const contact = contacts.find(c => c.id === targetContactId);
        if (!contact) return;

        // Переключаемся в целевой чат
        selectContact(targetContactId);

        // Отправляем пересланное сообщение
        sendMessage(origMsg.text || '', origMsg.voice || null, origMsg.file || null, originalSender);
    }

    // ==============================================================================
    // 23. ОЧИСТКА ИСТОРИИ, СТАТУС НАБОРА И ОТЧЕТЫ О ПРОЧТЕНИИ
    // ==============================================================================
    window.clearChatHistory = function(contactId) {
        if (!contactId) return;
        if (!confirm('Вы действительно хотите очистить историю этого чата? Все сообщения будут стерты.')) return;
        messages[contactId] = [];
        delete pinnedMessages[contactId];
        delete chatDrafts[contactId];
        saveMessages();
        idbSet(STORAGE_KEY_PINNED, pinnedMessages);
        idbSet(STORAGE_KEY_DRAFTS, chatDrafts);

        if (activeContactId === contactId) {
            renderMessages();
            updatePinnedBanner(contactId);
        }
        renderContactList();
        const contactModal = document.getElementById('modal-contact-info');
        if (contactModal) contactModal.style.display = 'none';
    };

    if (elBtnClearChatHistory) {
        elBtnClearChatHistory.addEventListener('click', () => {
            if (activeContactId) {
                window.clearChatHistory(activeContactId);
            }
        });
    }

    let lastTypingSentTs = 0;
    let typingTimer = null;

    function notifyTyping() {
        if (!activeContactId || !ws || ws.readyState !== WebSocket.OPEN) return;
        const now = Date.now();
        if (now - lastTypingSentTs < 2500) return;
        lastTypingSentTs = now;

        const contact = contacts.find(c => c.id === activeContactId);
        if (!contact) return;

        if (contact.isGroup) {
            (contact.memberIds || []).forEach(mId => {
                if (mId !== (identity ? identity.id : '')) {
                    ws.send(JSON.stringify({ action: 'typing', to: mId }));
                }
            });
        } else {
            ws.send(JSON.stringify({ action: 'typing', to: contact.id }));
        }
    }

    function handleIncomingTyping(senderId) {
        if (!contacts || contacts.length === 0) return;
        const typingContact = contacts.find(c => c.isGroup ? (c.memberIds || []).includes(senderId) : c.id === senderId);
        if (typingContact) {
            typingUsers.add(typingContact.id);
            renderContactList();
        }

        if (!activeContactId) return;
        const contact = contacts.find(c => c.id === activeContactId);
        if (!contact) return;

        const isCurrentChat = contact.isGroup ? (contact.memberIds || []).includes(senderId) : activeContactId === senderId;
        if (!isCurrentChat) return;

        const sender = contacts.find(c => c.id === senderId);
        const name = sender ? sender.name : 'Собеседник';

        const statusText = document.querySelector('.contact-status-text');
        if (statusText) {
            statusText.textContent = `${name} печатает...`;
            statusText.style.color = 'var(--primary)';
        }

        const typingRow = document.getElementById('chat-typing-row');
        if (typingRow) {
            typingRow.innerHTML = `<span>${escapeHtml(name)} печатает</span><span class="typing-dot"></span><span class="typing-dot"></span><span class="typing-dot"></span>`;
            typingRow.style.display = 'flex';
        }

        if (typingTimer) clearTimeout(typingTimer);
        typingTimer = setTimeout(() => {
            if (typingContact) {
                typingUsers.delete(typingContact.id);
                renderContactList();
            }
            if (statusText) {
                statusText.textContent = 'Сквозной шифр активен • Сервер слеп';
                statusText.style.color = '';
            }
            if (typingRow) {
                typingRow.style.display = 'none';
            }
        }, 3000);
    }

    function handleRemoteReadReceipt(messageId) {
        if (!messageId) return;
        for (const cId in messages) {
            const msg = messages[cId].find(m => m.id === messageId);
            if (msg) {
                msg.isRead = true;
                saveMessages();
                const statusEl = document.getElementById(`status_${messageId}`);
                if (statusEl) {
                    statusEl.textContent = '✓✓';
                    statusEl.style.color = '#38bdf8';
                }
                break;
            }
        }
    }

    function escapeJsArg(str) {
        return (str || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '');
    }

    // Вспомогательные функции
    function getColorFromHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = str.charCodeAt(i) + ((hash << 5) - hash);
        }
        const hue = Math.abs(hash % 360);
        return `hsl(${hue}, 65%, 40%)`;
    }

    function escapeHtml(str) {
        return (str || '').replace(/[&<>'"]/g, tag => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
        }[tag] || tag));
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    // ==============================================================================
    // QR-КОДЫ: ПОКАЗАТЬ СВОЙ QR И СКАНИРОВАТЬ КАМЕРОЙ (jsQR.js + qrcode.js)
    // ==============================================================================
    const elBtnShowMyQr = document.getElementById('btn-show-my-qr');
    const elModalMyQr = document.getElementById('modal-my-qr');
    const elBtnCloseMyQr = document.getElementById('btn-close-my-qr');
    const elMyQrName = document.getElementById('my-qr-name');
    const elMyQrCanvas = document.getElementById('my-qr-canvas');
    const elBtnCopyMyQrLink = document.getElementById('btn-copy-my-qr-link');

    const elBtnScanContactQr = document.getElementById('btn-scan-contact-qr');
    const elModalQrScanner = document.getElementById('modal-qr-scanner');
    const elBtnCloseQrScanner = document.getElementById('btn-close-qr-scanner');
    const elBtnCancelQrScan = document.getElementById('btn-cancel-qr-scan');
    const elQrCameraVideo = document.getElementById('qr-camera-video');
    const elQrScanError = document.getElementById('qr-scan-error');

    window.activeQrScanner = null;

    if (elBtnShowMyQr && elModalMyQr) {
        elBtnShowMyQr.addEventListener('click', () => {
            if (!identity) return;
            if (elMyQrName) elMyQrName.textContent = identity.name || currentUserProfile;
            const qrData = JSON.stringify({
                name: identity.name || currentUserProfile,
                pub: identity.publicKeyB64,
                id: identity.id
            });
            if (window.SovereignQr && elMyQrCanvas) {
                SovereignQr.renderToCanvas(elMyQrCanvas, qrData);
            }
            elModalMyQr.style.display = 'flex';
            if (window.history && window.history.pushState) {
                window.history.pushState({ modal: 'my-qr' }, '');
            }
        });

        const elBtnQuickMyQr = document.getElementById('btn-quick-my-qr');
        if (elBtnQuickMyQr) {
            elBtnQuickMyQr.addEventListener('click', (e) => {
                e.stopPropagation();
                elBtnShowMyQr.click();
            });
        }
    }

    if (elBtnCloseMyQr && elModalMyQr) {
        elBtnCloseMyQr.addEventListener('click', () => {
            elModalMyQr.style.display = 'none';
        });
    }

    if (elBtnCopyMyQrLink) {
        elBtnCopyMyQrLink.addEventListener('click', () => {
            const elInviteLink = document.getElementById('display-my-invite-link');
            if (elInviteLink && elInviteLink.value) {
                navigator.clipboard.writeText(elInviteLink.value).then(() => {
                    alert('Ссылка-приглашение скопирована в буфер обмена!');
                }).catch(() => {
                    prompt('Скопируйте ссылку:', elInviteLink.value);
                });
            }
        });
    }

    if (elBtnScanContactQr && elModalQrScanner) {
        elBtnScanContactQr.addEventListener('click', async () => {
            if (elQrScanError) elQrScanError.style.display = 'none';
            elModalQrScanner.style.display = 'flex';
            if (window.history && window.history.pushState) {
                window.history.pushState({ modal: 'qr-scanner' }, '');
            }

            if (window.SovereignQr && elQrCameraVideo) {
                window.activeQrScanner = await SovereignQr.startScanner(
                    elQrCameraVideo,
                    (scannedText) => {
                        handleQrScanned(scannedText);
                    },
                    (errText) => {
                        if (elQrScanError) {
                            elQrScanError.textContent = errText;
                            elQrScanError.style.display = 'block';
                        }
                    }
                );
            }
        });
    }

    function closeQrScanner() {
        if (window.activeQrScanner && window.activeQrScanner.stop) {
            window.activeQrScanner.stop();
            window.activeQrScanner = null;
        }
        if (elModalQrScanner) elModalQrScanner.style.display = 'none';
    }

    if (elBtnCloseQrScanner) elBtnCloseQrScanner.addEventListener('click', closeQrScanner);
    if (elBtnCancelQrScan) elBtnCancelQrScan.addEventListener('click', closeQrScanner);

    function handleQrScanned(rawText) {
        closeQrScanner();
        let name = '';
        let pub = '';

        try {
            if (rawText.startsWith('{') && rawText.endsWith('}')) {
                const parsed = JSON.parse(rawText);
                name = parsed.name || '';
                pub = parsed.pub || '';
            } else if (rawText.includes('invite=')) {
                const b64 = rawText.split('invite=')[1];
                const decoded = JSON.parse(decodeURIComponent(atob(b64)));
                name = decoded.name || '';
                pub = decoded.pub || '';
            } else {
                pub = rawText.trim();
            }
        } catch (e) {
            pub = rawText.trim();
        }

        const inputName = document.getElementById('input-contact-name');
        const inputKey = document.getElementById('input-contact-pubkey');
        if (inputName && name) inputName.value = name;
        if (inputKey && pub) inputKey.value = pub;

        if (name && pub) {
            // Если QR-код содержит и имя и ключ — мгновенно добавляем контакт и открываем чат
            const btnConfirm = document.getElementById('btn-confirm-add-contact');
            if (btnConfirm) {
                btnConfirm.click();
                return;
            }
        }

        if (elModalAddContact && elModalAddContact.style.display === 'none') {
            elModalAddContact.style.display = 'flex';
        }
    }

    // ==============================================================================
    // ПЕРЕХВАТ СИСТЕМНОЙ КНОПКИ / ЖЕСТА «НАЗАД» (ANDROID & WEB)
    // ==============================================================================
    window.handleAndroidBack = function () {
        // 0. Контекстное меню / Action Sheet
        if (elContextMenu && elContextMenu.style.display !== 'none') {
            closeContextMenu();
            return true;
        }

        // 1. Сканер QR-кода
        if (elModalQrScanner && elModalQrScanner.style.display !== 'none') {
            closeQrScanner();
            return true;
        }

        // 2. Мой QR-код
        if (elModalMyQr && elModalMyQr.style.display !== 'none') {
            elModalMyQr.style.display = 'none';
            return true;
        }

        // 3. Полноэкранный просмотр фото (Lightbox)
        if (elModalLightbox && elModalLightbox.style.display !== 'none') {
            elModalLightbox.style.display = 'none';
            return true;
        }

        // 4. Активный экран звонка
        const elCallOverlay = document.getElementById('call-overlay');
        if (elCallOverlay && elCallOverlay.style.display !== 'none') {
            if (window.hangupCall) window.hangupCall();
            return true;
        }

        // 5. Любые открытые модальные окна
        const openModals = Array.from(document.querySelectorAll('.modal-backdrop')).filter(m => m.style.display !== 'none');
        if (openModals.length > 0) {
            openModals[openModals.length - 1].style.display = 'none';
            return true;
        }

        // 6. Если открыт диалог на смартфоне — возвращаемся к списку чатов
        const appContainer = document.getElementById('app-container');
        if ((appContainer && appContainer.classList.contains('has-active-chat')) || (activeContactId && window.innerWidth <= 768)) {
            deselectContact();
            return true;
        }

        // 7. Разрешаем системе свернуть приложение
        return false;
    };

    // Слушатель системной кнопки "Назад" в Cordova / Capacitor
    document.addEventListener('backbutton', function (e) {
        if (window.handleAndroidBack && window.handleAndroidBack()) {
            e.preventDefault();
            e.stopPropagation();
        }
    }, false);

    // Слушатель жеста "Назад" в браузере / PWA
    window.addEventListener('popstate', function () {
        if (window.handleAndroidBack) {
            window.handleAndroidBack();
        }
    });

    // Запуск приложения
    try {
        await initIdentity();
    } catch (e) {
        console.error('[CRITICAL] Ошибка инициализации криптографии:', e);
        localStorage.removeItem(STORAGE_KEY_IDENTITY);
        try {
            await initIdentity();
        } catch (e2) {
            alert('Криптографическая ошибка: ' + e2.message);
        }
    }

    await loadStorageData();
    await fetchServerInfo();
    connectWebSocket();
})();
