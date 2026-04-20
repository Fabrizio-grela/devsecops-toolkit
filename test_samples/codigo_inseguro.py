import os
import hashlib
import requests

def hacer_ping(ip_usuario):
    # ☢️ MAL: Un atacante podría enviar "8.8.8.8; rm -rf /" y borrar tu servidor
    os.system("ping -c 4 " + ip_usuario)

def calcular_hash(texto):
    # ☢️ MAL: MD5 está roto, se debería usar SHA-256
    return hashlib.md5(texto.encode()).hexdigest()

def calculadora_web(formula):
    # ☢️ PÉSIMO: eval() ejecuta literalmente cualquier código que le pases
    resultado = eval(formula)
    return resultado

def consultar_api():
    # ☢️ MAL: Desactiva la verificación del certificado (peligro de robo de datos)
    respuesta = requests.get("https://api.banco.com/datos", verify=False)
    return respuesta