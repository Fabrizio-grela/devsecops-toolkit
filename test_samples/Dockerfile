# 🏗️ FALLO 1: Usar 'latest' o no especificar versión. Si la imagen base cambia, el server se rompe o se infecta.
FROM ubuntu:latest

# 🏗️ FALLO 2: Quemar secretos en el código fuente. Cualquiera que lea el Dockerfile tiene la clave de la base de datos.
ENV DB_PASSWORD=Admin1234!
ARG API_TOKEN=sk-12345abcdef

RUN apt-get update && apt-get install -y openssh-server postgresql

# 🏗️ FALLO 3: Exponer puertos críticos de administración directamente a internet (SSH y base de datos).
EXPOSE 22 5432 80

# 🏗️ FALLO 4 (Global): Como en ninguna línea usamos el comando "USER", este contenedor 
# va a ejecutar todo como el superadministrador ROOT. Si un hacker entra, es dueño de la máquina.
CMD ["/usr/sbin/sshd", "-D"]