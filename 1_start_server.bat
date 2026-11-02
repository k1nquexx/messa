@echo off
chcp 65001 > nul
echo [MESSA] Starting Native C# Sovereign Relay Server...
"%USERPROFILE%\.dotnet\dotnet.exe" run --project src\Messa.Server\Messa.Server.csproj
pause
