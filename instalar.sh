#!/bin/bash

echo "====================================="
echo "  Instalador de DevSecOps Toolkit"
echo "====================================="

# Verifica que el binario de Linux/Mac existe
if [ ! -f "./dist/devsec" ]; then
    echo "❌ Error: No se encontró el binario 'devsec' en la carpeta /dist."
    exit 1
fi

echo "[*] Moviendo el ejecutable a /usr/local/bin..."
# Usa sudo porque esa carpeta requiere permisos de admin
sudo cp ./dist/devsec /usr/local/bin/devsec

echo "[*] Otorgando permisos de ejecución..."
sudo chmod +x /usr/local/bin/devsec

echo "🎉 ¡INSTALACIÓN COMPLETA! 🎉"
echo "Ya puedes escribir 'devsec' en tu terminal."