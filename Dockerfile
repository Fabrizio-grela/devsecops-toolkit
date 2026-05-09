# Usa una imagen base de Python ligera
FROM python:3.10-slim

# Instala las dependencias del sistema (git para clonar repos y Trivy para IaC)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Instala Trivy
RUN wget https://github.com/aquasecurity/trivy/releases/download/v0.51.1/trivy_0.51.1_Linux-64bit.deb && \
    dpkg -i trivy_0.51.1_Linux-64bit.deb && \
    rm trivy_0.51.1_Linux-64bit.deb

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
CMD ["--help"]