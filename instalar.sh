#!/bin/bash
# Instalador para v1 (Source Code)
echo "[*] Configurando DevSec v1..."
ROOT_DIR=$(pwd)
chmod +x "$ROOT_DIR/main.py"
sudo ln -sf "$ROOT_DIR/main.py" /usr/local/bin/devsec
echo "[+] Instalación v1 lista. Ahora podés usar el comando: devsec"