#!/bin/bash

# Crear directorio oculto en el home del usuario
mkdir -p "$HOME/.devsec"

# Crear archivo vacío para evitar que Docker cree un directorio en su lugar
if [ ! -f "$HOME/.devsec/config.json" ]; then
    echo "{}" > "$HOME/.devsec/config.json"
fi

# Ejecutar contenedor mapeando el archivo de configuracion y la ruta actual
docker run -it --rm \
    -v "$HOME/.devsec/config.json:/app/config.json" \
    -v "$HOME:/host" \
    -v "$(pwd):/data" \
    fyto02/devsecops-toolkit:latest /data "$@"