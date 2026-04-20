# Script de Instalación Automática - DevSec Toolkit
$InstallDir = "$env:USERPROFILE\DevSecToolkit"
$ExePath = ".\dist\devsec.exe"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Instalador de DevSecOps Toolkit" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# 1. Verificar que el ejecutable existe
if (-Not (Test-Path $ExePath)) {
    Write-Host "[X] Error: No se encontro devsec.exe en la carpeta /dist." -ForegroundColor Red
    Write-Host "Asegurate de ejecutar este script desde la carpeta principal del proyecto." -ForegroundColor Yellow
    Pause
    Exit
}

# 2. Crear la carpeta base y copiar el archivo
Write-Host "[*] Creando directorio en $InstallDir..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path $ExePath -Destination "$InstallDir\devsec.exe" -Force
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