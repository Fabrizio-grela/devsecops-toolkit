# Script de Instalación Automática - DevSec Toolkit
$InstallDir = "$env:USERPROFILE\DevSecToolkit"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Instalador de DevSecOps Toolkit" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

Write-Host "[*] Instalando dependencias de Python..."
pip install -r requirements.txt

# 1. Crear la carpeta base
Write-Host "[*] Creando directorio en $InstallDir..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# 2. Crear wrapper devsec.bat para ejecutar el código fuente
$ProjectPath = (Get-Location).Path
$BatContent = "@echo off`npython `"$ProjectPath\main.py`" %*"
Set-Content -Path "$InstallDir\devsec.bat" -Value $BatContent
Write-Host "[OK] Archivo copiado exitosamente." -ForegroundColor Green

# 3. Editar las Variables de Entorno (PATH) automaticamente
Write-Host "[*] Configurando Variables de Entorno..."
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")

if ($UserPath -notmatch [regex]::Escape($InstallDir)) {
    [Environment]::SetEnvironmentVariable("PATH", "$UserPath;$InstallDir", "User")
    Write-Host "[OK] Comando 'devsec' registrado en el sistema." -ForegroundColor Green
} else {
    Write-Host "[!] El comando ya estaba registrado." -ForegroundColor Yellow
}

Write-Host "`n*** INSTALACION COMPLETA ***" -ForegroundColor Cyan
Write-Host "Por favor, cerra esta ventana y abri una terminal nueva." -ForegroundColor White
Write-Host "Ya podes escribir el comando 'devsec' en cualquier carpeta." -ForegroundColor White
Pause