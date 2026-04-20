import os
import re
import requests
import time

# Configuración de búsqueda
IGNORAR_CARPETAS = ['.git', 'venv', '__pycache__', 'node_modules', 'reportes', 'modulos']
EXTENSIONES_VALIDAS = ('.py', '.js', '.txt', '.json', '.env', '.html', '.yml', '.yaml')

# Regex para detectar direcciones IP públicas (IPv4)
REGEX_IP = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

def consultar_virustotal(ip, api_key):
    """Consulta la reputación de una IP en la base de datos de VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        respuesta = requests.get(url, headers=headers)
        if respuesta.status_code == 200:
            datos = respuesta.json()
            # Extraccion de las estadísticas del último análisis
            stats = datos['data']['attributes']['last_analysis_stats']
            maliciosos = stats['malicious']
            sospechosos = stats['suspicious']
            
            if maliciosos > 0:
                return f"🚨 ALERTA: Detectada como MALICIOSA por {maliciosos} motores."
            elif sospechosos > 0:
                return f"⚠️ AVISO: Marcada como sospechosa ({sospechosos} motores)."
            else:
                return "✅ Limpia (0 detecciones)."
        elif respuesta.status_code == 401:
            return "❌ Error: API Key inválida o no configurada."
        else:
            return f"❓ Estado desconocido (Código {respuesta.status_code})"
    except Exception as e:
        return f"❌ Error de conexión: {str(e)}"

def analizar(ruta_proyecto):
    #  se intenta obtener la API Key de las variables de entorno del sistema
    api_key = os.getenv("VT_API_KEY")
    
    if not api_key:
        return "⚠️ Módulo omitido: Falta configurar la variable de entorno VT_API_KEY."

    ips_encontradas = set()
    hallazgos = []

    # 1. Fase de Recolección: Busca IPs en los archivos
    for raiz, directorios, archivos in os.walk(ruta_proyecto):
        directorios[:] = [d for d in directorios if d not in IGNORAR_CARPETAS]
        
        for archivo in archivos:
            if archivo.endswith(EXTENSIONES_VALIDAS):
                ruta_completa = os.path.join(raiz, archivo)
                try:
                    with open(ruta_completa, 'r', encoding='utf-8') as f:
                        contenido = f.read()
                        ips = re.findall(REGEX_IP, contenido)
                        for ip in ips:
                            # Filtramos IPs locales/privadas (127.x, 192.168.x, etc.)
                            if not ip.startswith(('127.', '192.168.', '10.', '172.')):
                                ips_encontradas.add(ip)
                except Exception:
                    pass

    if not ips_encontradas:
        return "No se encontraron IPs públicas para analizar."

    # 2. Fase de Inteligencia: Consulta cada IP encontrada
    for ip in ips_encontradas:
        resultado_api = consultar_virustotal(ip, api_key)
        hallazgos.append(f"IP {ip} -> {resultado_api}")
        # Pausa de 15 segundos entre IPs para no saturar la cuenta gratuita 
        # (Si tenés cuenta premium, podés bajar este tiempo)
        time.sleep(15)

    # 3. Formateo de reporte final
    resultado_final = f"Se analizaron {len(ips_encontradas)} IPs únicas:\n"
    for h in hallazgos:
        resultado_final += f"        - 🌐 {h}\n"
    
    return resultado_final