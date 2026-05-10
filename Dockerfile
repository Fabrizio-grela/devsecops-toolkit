# Usa una imagen base de Python ligera
FROM python:3.10-slim

# Instala las dependencias del sistema (git para clonar repos y Trivy para IaC)
# Se instala Trivy desde el repositorio oficial para mayor estabilidad.
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Dependencias para el repo de Trivy y para la herramienta
    git \
    wget \
    apt-transport-https \
    gnupg \
    lsb-release \
    # Instalar la clave GPG de Trivy
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    # Agregar el repositorio de Trivy
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" > /etc/apt/sources.list.d/trivy.list \
    # Actualizar e instalar Trivy
    && apt-get update \
    && apt-get install -y trivy \
    # Limpiar caché para reducir el tamaño de la imagen
    && rm -rf /var/lib/apt/lists/*

# Establece el directorio de trabajo
WORKDIR /app

# Copia solo el archivo de dependencias para aprovechar la caché de Docker
COPY requirements.txt .

# Instala las dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia el resto del código del proyecto
COPY . .

# Define el punto de entrada para que el contenedor sea ejecutable
# Esto permite pasar argumentos directamente al script main.py
ENTRYPOINT ["python", "main.py"]

# Define un comando por defecto para mostrar la ayuda si no se pasan argumentos
CMD []