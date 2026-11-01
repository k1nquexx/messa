// ==============================================================================
// NATIVE DESKTOP WRAPPER (ELECTRON)
// Запускает мессенджер как полноценное настольное Windows-приложение
// ==============================================================================

const { app, BrowserWindow } = require('electron');
const path = require('node:path');
const { fork } = require('node:child_process');

let serverProcess = null;
let mainWindow = null;

// 1. Автоматический запуск встроенного сервера в фоновом режиме
function startRelayServer() {
    const serverPath = path.join(__dirname, '..', 'server', 'server.js');
    serverProcess = fork(serverPath, [], {
        stdio: 'pipe'
    });

    serverProcess.stdout.on('data', (data) => {
        console.log(`[Relay Engine]: ${data}`);
    });

    serverProcess.stderr.on('data', (data) => {
        console.error(`[Relay Engine ERR]: ${data}`);
    });
}

// 2. Создание главного окна приложения
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1150,
        height: 780,
        minWidth: 480,
        minHeight: 640,
        title: 'Суверенный Мессенджер',
        backgroundColor: '#0a0e17',
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true
        },
        autoHideMenuBar: true
    });

    // Загружаем интерфейс из локального сервера
    mainWindow.loadURL('http://127.0.0.1:8080');

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

app.whenReady().then(() => {
    startRelayServer();
    // Даем серверу полсекунды на запуск сокета
    setTimeout(createWindow, 600);

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    // При закрытии окна завершаем фоновый процесс сервера
    if (serverProcess) {
        serverProcess.kill();
    }
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('quit', () => {
    if (serverProcess) {
        serverProcess.kill();
    }
});
