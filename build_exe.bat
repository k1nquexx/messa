@echo off
chcp 65001 > nul
echo [CIPHER BUILD] Compiling native CIPHER.exe...

taskkill /F /IM CIPHER.exe >nul 2>&1

set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
set WPF=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF

"%CSC%" /nologo /target:winexe /out:CIPHER.exe /win32icon:app.ico /lib:"%WPF%" /r:PresentationCore.dll,PresentationFramework.dll,WindowsBase.dll,System.Xaml.dll,System.Web.Extensions.dll Program.cs

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] CIPHER.exe compiled successfully!
) else (
    echo [ERROR] Compilation failed!
)
