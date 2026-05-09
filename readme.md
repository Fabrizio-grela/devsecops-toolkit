# 🛡️ DevSecOps Toolkit v2.0

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

**DevSecOps Toolkit** es una potente suite de seguridad diseñada para automatizar el análisis estático y la detección de amenazas en entornos de desarrollo. Desarrollada pensando en la velocidad y la eficiencia, la herramienta utiliza procesamiento multi-núcleo para auditar proyectos complejos en segundos.

---

## 🚀 ¿Qué hace esta herramienta?

El toolkit actúa como un "perro guardián" que analiza tu proyecto desde diferentes ángulos para encontrar vulnerabilidades antes de que lleguen a producción.

### 🧩 Módulos Incluidos:

* **🔑 Secrets & Leaks:** Escanea archivos en busca de claves de API, tokens de AWS, contraseñas y otros secretos "hardcoded".
* **☢️ SAST (Static Application Security Testing):** Auditoría multilingüe (Python, JS, Java, PHP, C/C++) para detectar inyecciones de código y fallos lógicos.
* **🐛 SCA (Software Composition Analysis):** Analiza dependencias (`requirements.txt`, `package.json`, `pom.xml`, `go.mod`) buscando vulnerabilidades (CVEs).
* **🏗️ IaC Scanner:** Audita archivos `Dockerfile`, manifiestos de Kubernetes y Terraform para detectar configuraciones inseguras.
* **🌐 Threat Intel:** Integración con **VirusTotal** para verificar si IPs extraídas del código son maliciosas.
* **☁️ Cloud Security (AWS):** Audita directamente tu cuenta de Amazon Web Services en busca de Buckets S3 públicos o usuarios IAM sin MFA.
* **🤖 Remediación Automática (IA):** Genera parches y código seguro al instante utilizando modelos de IA (Gemini, ChatGPT, Claude u Ollama).

---

## 🛠️ Instalación

### 🪟 Windows
1. Descarga el repositorio y asegurate de tener Python instalado (Opcional: andá a la sección de Releases y descargá el devsec.exe).
2. Si usás el código fuente, hacé clic derecho sobre el archivo `instalar.ps1` y seleccioná **"Ejecutar con PowerShell"**.
3. Reiniciá tu terminal (CMD o PowerShell).
4. ¡Listo! Escribí `devsec` para empezar.

🐧 Linux & 🍎 macOS (Código Fuente)
1. Cloná el repositorio:

   git clone https://github.com/Fabrizio-grela/devsecops-toolkit.git

   cd devsecops-toolkit

2. Instalá las dependencias necesarias:

   pip install -r requirements.txt

3. Dale permisos al instalador y ejecutalo:

   chmod +x instalar.sh
   
   ./instalar.sh

4. ¡Listo! Ahora podés ejecutar la herramienta simplemente escribiendo `devsec` en cualquier terminal.

### 🐳 Usando Docker (Recomendado para la comunidad)
Si no deseas instalar dependencias, Python ni Trivy en tu máquina, puedes usar el contenedor preconfigurado:

1. Construye la imagen localmente:
   ```bash
   docker build -t devsecops-toolkit .
   ```
2. Ejecuta el escáner montando el directorio actual dentro del contenedor:
   ```bash
   docker run --rm -v $(pwd):/app devsecops-toolkit --todo
   ```
   *(En Windows usa `${PWD}` en PowerShell o `%cd%` en CMD en lugar de `$(pwd)`)*

---

## ⚙️ Configuración y Variables de Entorno

En el primer uso local, un asistente interactivo te guiará para configurar las API Keys. Si prefieres usar Docker o automatizar el Toolkit, puedes pasar las credenciales directamente como **Variables de Entorno**:
* `VT_API_KEY`: Para el motor de VirusTotal.
* `GEMINI_API_KEY`, `OPENAI_API_KEY` o `ANTHROPIC_API_KEY`: Para sugerencias de remediación con IA.
* `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`: Para el escáner de Cloud Security.

💻 Modo de Uso
DevSecOps Toolkit cuenta con dos formas de ejecución:

1. Modo Interactivo (Recomendado)
Simplemente escribe el comando solo y sigue las instrucciones en pantalla: `devsec`
La herramienta te guiará para elegir la ruta del proyecto y qué motores ejecutar mediante un menú numérico.

2. Modo CLI (Avanzado)
Puedes pasar argumentos directamente para automatizar escaneos en pipelines de CI/CD:
* `devsec . --todo`: Escanea la carpeta actual con todos los motores.
* `devsec /ruta/proyecto --leaks --sast`: Ejecuta solo los módulos de secretos y código SAST.

## 📊 Reportes Interactivos

Al finalizar el escaneo, se genera un **reporte HTML standalone y moderno**. Incluye un resumen visual de hallazgos por severidad, fragmentos de código vulnerable resaltados, y las mitigaciones de código seguro generadas por la IA con un botón para **📋 Copiar al Portapapeles**.

⚙️ Requisitos Técnicos
Python 3.9+ (solo si corres el código fuente).

Multi-core CPU: Optimizado para procesadores modernos (aprovecha todos los hilos disponibles).

Conexión a Internet: Requerida únicamente para el módulo de Threat Intel (VirusTotal).

⚖️ Disclaimer
Este software fue desarrollado con fines educativos y de auditoría ética. El autor no se hace responsable por el uso indebido de esta herramienta en sistemas sin autorización previa.

Desarrollado de forma independiente como herramienta de código abierto.