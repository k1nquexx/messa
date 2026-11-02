const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('[MOBILE BUILD] Синхронизация веб-ресурсов в Android...');
execSync('npx cap copy', { stdio: 'inherit' });

console.log('[MOBILE BUILD] Сборка Android APK через Gradle...');
const androidDir = path.join(__dirname, 'mobile', 'android');
const gradlewCmd = process.platform === 'win32' ? 'gradlew.bat' : './gradlew';
execSync(`${gradlewCmd} assembleDebug`, { cwd: androidDir, stdio: 'inherit' });

const builtApk = path.join(androidDir, 'app', 'build', 'outputs', 'apk', 'debug', 'app-debug.apk');
if (fs.existsSync(builtApk)) {
    fs.copyFileSync(builtApk, path.join(__dirname, 'mobile', 'SovereignMessenger.apk'));
    fs.copyFileSync(builtApk, path.join(__dirname, 'mobile', 'CIPHER.apk'));
    fs.copyFileSync(builtApk, path.join(__dirname, 'CIPHER.apk'));
    console.log('[SUCCESS] Актуальные APK успешно сохранены в CIPHER.apk, mobile/CIPHER.apk и mobile/SovereignMessenger.apk');
} else {
    console.error('[ERROR] Файл app-debug.apk не найден после сборки');
    process.exit(1);
}
