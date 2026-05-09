@echo off
echo =====================================
echo   Subir cambios a GitHub (Rama MAIN)
echo =====================================
echo.
set /p mensaje="Ingresa el mensaje para este cambio: "
git add .
git commit -m "%mensaje%"
git checkout main
git merge v2-development
git push origin main
git checkout v2-development
echo.
echo [OK] ¡Cambios fusionados y subidos a MAIN con exito!
pause