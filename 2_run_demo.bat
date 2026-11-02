@echo off
chcp 65001 > nul
echo [MESSA] Starting Native Avalonia UI Client (Skia)...
"%USERPROFILE%\.dotnet\dotnet.exe" run --project src\Messa.Desktop\Messa.Desktop.csproj
