# 🛡️ DevSecOps Toolkit v2.0

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="Platform">
</p>

**DevSecOps Toolkit** es una suite de seguridad integral y de alto rendimiento, diseñada para automatizar la detección de vulnerabilidades y malas prácticas en el ciclo de vida del desarrollo de software. Construida con un enfoque en la velocidad, utiliza **procesamiento multi-núcleo** para auditar proyectos complejos en segundos y ofrece **remediación automática con IA** para acelerar la corrección de fallos.

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

2. Dale permisos al instalador y ejecútalo con `sudo`:

   chmod +x instalar.sh
   
   ./instalar.sh

4. ¡Listo! Ahora podés ejecutar la herramienta simplemente escribiendo `devsec` en cualquier terminal.

### 🐳 Usando Docker (Recomendado para entornos aislados y CI/CD)
Si no deseas instalar dependencias, Python ni Trivy en tu máquina, puedes usar el contenedor preconfigurado:
> **Requisito previo:** Asegurate de tener [Docker Desktop](https://www.docker.com/products/docker-desktop/) instalado y en ejecución en tu sistema.
#### Opción A: Usar la imagen pública desde Docker Hub
1. Descargá la imagen oficial desde Docker Hub. **(¡Recordá reemplazar `tu-usuario-de-dockerhub`!)**
```bash
docker pull fabriziogrela/devsecops-toolkit:latest
```

#### Opción B: Construir la imagen localmente
Si preferís construir la imagen directamente desde el código fuente:
```bash
# Esto crea una imagen local llamada 'devsecops-toolkit:latest'
docker build -t fabriziogrela/devsecops-toolkit:latest .
```

### Cómo ejecutar el escáner con Docker
Una vez que tengas la imagen (ya sea descargada o construida localmente), ejecutá el escáner montando el directorio de tu proyecto dentro del contenedor:

#### Modo CLI (para CI/CD o scripts)

*   **🐧 Linux / macOS (bash):**
    ```bash
    docker run --rm -v $(pwd):/scan_target fabriziogrela/devsecops-toolkit:latest /scan_target --todo
    ```
*   **🪟 Windows (PowerShell):**
    ```powershell
    docker run --rm -v ${PWD}:/scan_target fabriziogrela/devsecops-toolkit:latest /scan_target --todo
    ```

#### Modo Interactivo (para usar el menú)

*   **🪟 Windows (PowerShell) / 🐧 Linux / 🍎 macOS:**
```bash
# El flag -it es para modo interactivo. El volumen 'devsec-config' guarda tu config.json.
docker run -it --rm -v "$(pwd):/scan_target" -v devsec-config:/data fabriziogrela/devsecops-toolkit:latest
```
   *(En Windows usa `${PWD}` en PowerShell o `%cd%` en CMD en lugar de `$(pwd)`)*

---

## ⚙️ Configuración

### Asistente Interactivo
La primera vez que ejecutes `devsec` localmente, un asistente te guiará para configurar las API Keys necesarias (IA y VirusTotal) y las guardará en un archivo `config.json`.

### Variables de Entorno (Prioridad Alta)
Para entornos automatizados (Docker, GitHub Actions), el toolkit prioriza las variables de entorno sobre el archivo `config.json`.

*   `VT_API_KEY`: Para el motor de VirusTotal.
*   `GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`: Para el proveedor de IA que desees usar.
*   `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`: Para el escáner de Cloud Security.

---

## 💻 Modo de Uso
DevSecOps Toolkit cuenta con dos formas de ejecución:

### 1. Modo Interactivo (Recomendado para uso local)
Ejecuta el comando sin argumentos para iniciar el asistente:
```bash
devsec
```
La herramienta te guiará para elegir la ruta del proyecto y qué motores ejecutar mediante un menú.

### 2. Modo CLI (Para automatización y CI/CD)
Pasa argumentos directamente para una ejecución silenciosa.

*   `devsec . --todo`: Escanea la carpeta actual con todos los motores.
*   `devsec /ruta/proyecto --leaks --sast`: Ejecuta solo los módulos de secretos y SAST.
*   `devsec https://github.com/usuario/repo.git --sca`: Clona un repositorio y ejecuta solo el análisis de dependencias.

### Ignorando Archivos (`.devsecignore`)
Crea un archivo `.devsecignore` en la raíz de tu proyecto para listar archivos o carpetas que deseas excluir del escaneo (funciona igual que un `.gitignore`).

## 📊 Reportes Interactivos

Al finalizar el escaneo, se genera un **reporte HTML standalone y moderno**. Incluye un resumen visual de hallazgos por severidad, fragmentos de código vulnerable resaltados, y las mitigaciones de código seguro generadas por la IA con un botón para **📋 Copiar al Portapapeles**.

⚖️ Disclaimer
Este software fue desarrollado con fines educativos y de auditoría ética. El autor no se hace responsable por el uso indebido de esta herramienta en sistemas sin autorización previa.

---

Desarrollado de forma independiente como una herramienta de código abierto. ¡Las contribuciones son bienvenidas!