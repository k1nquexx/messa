// ==============================================================================
// CIPHER BUILD RUNNER
// ==============================================================================
// ВНИМАНИЕ: Файл Program.cs является основным исходным кодом десктоп-клиента.
// Данный скрипт безопасно делегирует сборку батнику build_exe.bat без перезаписи исходников.
// ==============================================================================

const { execSync } = require('child_process');
const path = require('path');

console.log('[CIPHER] Запуск компиляции актуального Program.cs -> CIPHER.exe...');

try {
    execSync('build_exe.bat', {
        cwd: __dirname,
        stdio: 'inherit'
    });
} catch (err) {
    console.error('[ERR] Ошибка при компиляции CIPHER.exe:', err.message);
    process.exit(1);
}
