// ==============================================================================
// QR HELPER: ГЕНЕРАЦИЯ И СКАНИРОВАНИЕ QR-КОДОВ
// 100% автономно: генерация и распознавание на устройстве
// ==============================================================================

class SovereignQr {
    /**
     * Отрисовка стандартного QR-кода на Canvas
     */
    static renderToCanvas(canvas, text) {
        if (!window.qrcode) {
            console.error('Библиотека qrcode не загружена');
            return;
        }

        try {
            if (window.qrcode.stringToBytesFuncs && window.qrcode.stringToBytesFuncs['UTF-8']) {
                window.qrcode.stringToBytes = window.qrcode.stringToBytesFuncs['UTF-8'];
            }
            // Уровень коррекции ошибок 'M' (15% восстановления)
            const qr = window.qrcode(0, 'M');
            qr.addData(text);
            qr.make();

            const ctx = canvas.getContext('2d');
            const count = qr.getModuleCount();
            const width = canvas.width;
            const height = canvas.height;
            const cellSize = Math.floor(width / (count + 4));
            const offset = Math.floor((width - (count * cellSize)) / 2);

            ctx.fillStyle = '#ffffff';
            ctx.fillRect(0, 0, width, height);

            ctx.fillStyle = '#0a0e17';
            for (let r = 0; r < count; r++) {
                for (let c = 0; c < count; c++) {
                    if (qr.isDark(r, c)) {
                        ctx.fillRect(offset + c * cellSize, offset + r * cellSize, cellSize, cellSize);
                    }
                }
            }
        } catch (err) {
            console.error('Ошибка генерации QR:', err);
        }
    }

    /**
     * Запуск сканера камеры в реальном времени
     */
    static async startScanner(videoEl, onScan, onError) {
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            if (onError) onError('Камера не поддерживается вашим устройством');
            return null;
        }

        let stream = null;
        try {
            // Сначала пробуем заднюю камеру смартфона с мягким идеальным разрешением
            stream = await navigator.mediaDevices.getUserMedia({
                video: {
                    facingMode: { ideal: 'environment' },
                    width: { ideal: 1280 },
                    height: { ideal: 720 }
                }
            });
        } catch (e1) {
            console.warn('[QR] Режим environment недоступен, пробуем базовый video constraint:', e1);
            try {
                stream = await navigator.mediaDevices.getUserMedia({ video: true });
            } catch (err) {
                console.error('[QR] Ошибка доступа к камере:', err);
                if (onError) onError('Не удалось запустить камеру: ' + (err.message || 'Проверьте разрешения'));
                return null;
            }
        }

        try {
            videoEl.setAttribute('autoplay', '');
            videoEl.setAttribute('muted', '');
            videoEl.setAttribute('playsinline', '');
            videoEl.setAttribute('webkit-playsinline', '');
            videoEl.srcObject = stream;
            await videoEl.play();
        } catch (playErr) {
            console.warn('[QR] videoEl.play() warning:', playErr);
        }

        let scanning = true;
        const offscreenCanvas = document.createElement('canvas');
        const offscreenCtx = offscreenCanvas.getContext('2d', { willReadFrequently: true });

        const scanFrame = () => {
            if (!scanning) return;

            if (videoEl.readyState >= 2 && videoEl.videoWidth > 0) {
                offscreenCanvas.width = videoEl.videoWidth;
                offscreenCanvas.height = videoEl.videoHeight;
                offscreenCtx.drawImage(videoEl, 0, 0, offscreenCanvas.width, offscreenCanvas.height);

                const imageData = offscreenCtx.getImageData(0, 0, offscreenCanvas.width, offscreenCanvas.height);
                if (window.jsQR) {
                    const code = window.jsQR(imageData.data, imageData.width, imageData.height, {
                        inversionAttempts: 'attemptBoth'
                    });

                    if (code && code.data && code.data.trim()) {
                        scanning = false;
                        SovereignQr.playBeep();
                        stop();
                        onScan(code.data.trim());
                        return;
                    }
                }
            }

            requestAnimationFrame(scanFrame);
        };

        requestAnimationFrame(scanFrame);

        function stop() {
            scanning = false;
            if (stream) {
                stream.getTracks().forEach(track => track.stop());
                videoEl.srcObject = null;
            }
        }

        return { stop };
    }

    /**
     * Звуковой сигнал при успешном сканировании
     */
    static playBeep() {
        try {
            const AudioContext = window.AudioContext || window.webkitAudioContext;
            if (!AudioContext) return;
            const ctx = new AudioContext();
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.type = 'sine';
            osc.frequency.setValueAtTime(880, ctx.currentTime); // A5 note
            gain.gain.setValueAtTime(0.15, ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.1);
            osc.start(ctx.currentTime);
            osc.stop(ctx.currentTime + 0.1);
        } catch {}
    }
}

window.SovereignQr = SovereignQr;
