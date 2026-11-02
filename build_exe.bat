@echo off
chcp 65001 > nul
echo [MESSA BUILD] Publishing Native Avalonia Client (Self-Contained Single File)...
"%USERPROFILE%\.dotnet\dotnet.exe" publish src\Messa.Desktop\Messa.Desktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o dist\desktop
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Binary published to dist\desktop\Messa.Desktop.exe
) else (
    echo [ERROR] Build failed!
)
pause
