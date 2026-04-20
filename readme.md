# 🛡️ DevSecOps Toolkit v1.0

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

**DevSecOps Toolkit** es una potente suite de seguridad diseñada para automatizar el análisis estático y la detección de amenazas en entornos de desarrollo. Desarrollada pensando en la velocidad y la eficiencia, la herramienta utiliza procesamiento multi-núcleo para auditar proyectos complejos en segundos.

---

## 🚀 ¿Qué hace esta herramienta?

El toolkit actúa como un "perro guardián" que analiza tu proyecto desde diferentes ángulos para encontrar vulnerabilidades antes de que lleguen a producción.

### 🧩 Módulos Incluidos:

* **🔑 Secrets & Leaks:** Escanea archivos en busca de claves de API, tokens de AWS, contraseñas y otros secretos "hardcoded" que nunca deberían estar en el código.
* **☢️ SAST (Static Application Security Testing):** Analiza el código Python buscando funciones peligrosas (como `eval` o `os.system`) y malas prácticas que podrían permitir inyecciones.
* **🐛 SCA (Software Composition Analysis):** Revisa tu archivo `requirements.txt` y compara tus librerías con bases de datos de vulnerabilidades conocidas (CVE).
* **🏗️ IaC Scanner (Infrastructure as Code):** Audita archivos `Dockerfile` y configuraciones de infraestructura para detectar configuraciones inseguras (ej: correr como root o exponer puertos sensibles).
* **🌐 Threat Intel:** Integración con **VirusTotal** para verificar si las IPs o dominios mencionados en el código tienen reportes de actividad maliciosa.

---

## 🛠️ Instalación

La herramienta está diseñada para ser instalada como un comando global del sistema, permitiéndote ejecutar `devsec` en cualquier carpeta.

### 🪟 Windows
1. Descarga el repositorio y asegúrate de tener el archivo `devsec.exe` en la carpeta `dist/`.
2. Haz clic derecho sobre el archivo `instalar.ps1` y selecciona **"Ejecutar con PowerShell"**.
3. Reinicia tu terminal (CMD o PowerShell).
4. ¡Listo! Escribe `devsec` para empezar.

### 🐧 Linux & 🍎 macOS
1. Abre una terminal en la carpeta del proyecto.
2. Otorga permisos de ejecución al script:
   ```bash
   chmod +x instalar.sh
3.Ejecuta el instalador: ./instalar.sh
4.Ahora puedes ejecutar la herramienta simplemente escribiendo devsec.

💻 Modo de Uso
DevSecOps Toolkit cuenta con dos formas de ejecución:

1. Modo Interactivo (Recomendado)
Simplemente escribe el comando solo y sigue las instrucciones en pantalla: devsec
La herramienta te pedirá la ruta del proyecto y te permitirá elegir qué motores ejecutar mediante un menú numérico.

2. Modo CLI (Avanzado)
Puedes pasar argumentos directamente para automatizar escaneos en pipelines de CI/CD:

devsec . --todo: Escanea la carpeta actual con todos los motores.

devsec /ruta/proyecto --leaks --sast: Ejecuta solo los módulos de secretos y código.

⚙️ Requisitos Técnicos
Python 3.9+ (solo si corres el código fuente).

Multi-core CPU: Optimizado para procesadores modernos (aprovecha todos los hilos disponibles).

Conexión a Internet: Requerida únicamente para el módulo de Threat Intel (VirusTotal).

⚖️ Disclaimer
Este software fue desarrollado con fines educativos y de auditoría ética. El autor no se hace responsable por el uso indebido de esta herramienta en sistemas sin autorización previa.

Desarrollado de forma independiente como herramienta de código abierto.