@echo off
SETLOCAL

:: Crear directorio oculto en el perfil del usuario si no existe
IF NOT EXIST "%USERPROFILE%\.devsec" (
    mkdir "%USERPROFILE%\.devsec"
    attrib +h "%USERPROFILE%\.devsec"
)

:: Crear archivo vacio para que Docker lo monte como archivo y no como carpeta
IF NOT EXIST "%USERPROFILE%\.devsec\config.json" (
    echo {} > "%USERPROFILE%\.devsec\config.json"
)

docker run -it --rm ^
  -v "%USERPROFILE%\.devsec\config.json:/app/config.json" ^
  -v "%USERPROFILE%:/host" ^
  -v "%cd%:/data" ^
  fyto02/devsecops-toolkit:latest /data %*

ENDLOCAL