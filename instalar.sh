#!/bin/bash

echo "====================================="
echo "  Instalador de DevSecOps Toolkit"
echo "====================================="

echo "[*] Instalando dependencias de Python..."
pip3 install -r requirements.txt

echo "[*] Creando comando global 'devsec'..."
# Obtenemos la ruta absoluta de la carpeta actual del proyecto
DIR_ACTUAL=$(pwd)

# Creamos el script ejecutable (wrapper)
echo "#!/bin/bash" > devsec_temp
echo "python3 \"$DIR_ACTUAL/main.py\" \"\$@\"" >> devsec_temp

echo "[*] Moviendo el ejecutable a /usr/local/bin..."
# Usa sudo porque esa carpeta requiere permisos de admin
sudo mv devsec_temp /usr/local/bin/devsec

echo "[*] Otorgando permisos de ejecución..."
sudo chmod +x /usr/local/bin/devsec

echo "🎉 ¡INSTALACIÓN COMPLETA! 🎉"
echo "Ya puedes escribir 'devsec' en tu terminal."