@echo off
echo =====================================
echo   Subir cambios a GitHub (Push)
echo =====================================
echo.
set /p mensaje="Ingresa el mensaje para este cambio: "
git add .
git commit -m "%mensaje%"
git push
echo.
echo [OK] ¡Cambios subidos con exito!
pause