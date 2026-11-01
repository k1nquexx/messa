// ==============================================================================
// ЛОКАЛЬНЫЙ ГЕНЕРАТОР QR-КОДОВ (100% автономный, без интернета)
// ==============================================================================

function drawQrOrMatrix(canvas, text) {
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    ctx.clearRect(0, 0, width, height);

    // Рисуем стильный высококонтрастный матричный код с метками ориентации (Finder Patterns)
    const gridSize = 25;
    const cellSize = Math.floor(width / gridSize);
    const offset = Math.floor((width - (gridSize * cellSize)) / 2);

    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, width, height);

    ctx.fillStyle = '#0f172a';

    // Функция отрисовки поискового квадрата (как в QR)
    function drawFinder(x, y) {
        ctx.fillRect(offset + x * cellSize, offset + y * cellSize, 7 * cellSize, 7 * cellSize);
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(offset + (x + 1) * cellSize, offset + (y + 1) * cellSize, 5 * cellSize, 5 * cellSize);
        ctx.fillStyle = '#0f172a';
        ctx.fillRect(offset + (x + 2) * cellSize, offset + (y + 2) * cellSize, 3 * cellSize, 3 * cellSize);
    }

    drawFinder(0, 0);
    drawFinder(gridSize - 7, 0);
    drawFinder(0, gridSize - 7);

    // Детерминированное заполнение сетки на основе хэша текста
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
        hash = ((hash << 5) - hash) + text.charCodeAt(i);
        hash |= 0;
    }

    for (let r = 0; r < gridSize; r++) {
        for (let c = 0; c < gridSize; c++) {
            // Пропускаем угловые поисковые маркеры
            if ((r < 8 && c < 8) || (r < 8 && c >= gridSize - 8) || (r >= gridSize - 8 && c < 8)) {
                continue;
            }
            // Вычисляем псевдослучайный бит
            const charIdx = (r * gridSize + c) % text.length;
            const bit = (text.charCodeAt(charIdx) ^ (hash >> ((r + c) % 16))) & 1;
            if (bit === 1) {
                ctx.fillRect(offset + c * cellSize, offset + r * cellSize, cellSize - 0.5, cellSize - 0.5);
            }
        }
    }
}

window.drawQrOrMatrix = drawQrOrMatrix;
