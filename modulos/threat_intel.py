"""
Módulo Threat Intel (Threat Intelligence)
Consulta VirusTotal para verificar reputación de IPs y dominios encontrados en el código.
"""

import os
import re
import requests
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Dict, List, Any
from utils import logger, validar_ruta, obtener_archivos_proyecto, cache_global, EXTENSIONES_VALIDAS, ResultadoAnalisis, leer_archivo_completo

try:
    import aiohttp
except ImportError:
    aiohttp = None

# Regex para detectar direcciones IP públicas (IPv4)
REGEX_IP = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

# IPs privadas/locales a ignorar
IPS_PRIVADAS = {'127.', '192.168.', '10.', '172.'}

def es_ip_privada(ip: str) -> bool:
    """Verifica si una IP es privada/local."""
    return any(ip.startswith(prefijo) for prefijo in IPS_PRIVADAS)

async def consultar_virustotal_async(ip: str, api_key: str, session: Any, sem: asyncio.Semaphore) -> Dict[str, Any]:
    """Consulta la reputación de una IP en VirusTotal de forma asíncrona."""
    cache_key = f"vt_{ip}"
    resultado_cache = cache_global.get(cache_key)
    if resultado_cache is not None:
        return resultado_cache

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": api_key}

    async with sem:
        try:
            logger.debug(f"📡 Consultando VirusTotal (Async): {ip}")
            async with session.get(url, headers=headers, timeout=10) as respuesta:
                resultado = {'ip': ip, 'estado': 'desconocido', 'mensaje': '', 'maliciosos': 0}
                if respuesta.status == 200:
                    datos = await respuesta.json()
                    stats = datos['data']['attributes']['last_analysis_stats']
                    maliciosos = stats['malicious']
                    sospechosos = stats['suspicious']
                    resultado['maliciosos'] = maliciosos
                    if maliciosos > 0:
                        resultado['estado'] = 'malicioso'
                        resultado['mensaje'] = f"🚨 ALERTA: Detectada como MALICIOSA por {maliciosos} motores"
                    elif sospechosos > 0:
                        resultado['estado'] = 'sospechoso'
                        resultado['mensaje'] = f"⚠️ AVISO: Marcada como sospechosa ({sospechosos} motores)"
                    else:
                        resultado['estado'] = 'limpio'
                        resultado['mensaje'] = "✅ Limpia (0 detecciones)"
                elif respuesta.status == 401:
                    resultado['mensaje'] = "❌ Error: API Key inválida"
                else:
                    resultado['mensaje'] = f"❓ Estado desconocido (Código {respuesta.status})"
                
                cache_global.set(cache_key, resultado)
                return resultado
        except Exception as e:
            return {'ip': ip, 'estado': 'error', 'mensaje': f'Error: {str(e)}', 'maliciosos': 0}

def consultar_virustotal(ip: str, api_key: str) -> Dict[str, Any]:
    """Consulta la reputación de una IP en VirusTotal."""
    
    cache_key = f"vt_{ip}"
    resultado_cache = cache_global.get(cache_key)
    if resultado_cache is not None:
        logger.debug(f"✓ Caché hit: {ip}")
        return resultado_cache
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        logger.debug(f"📡 Consultando VirusTotal: {ip}")
        respuesta = requests.get(url, headers=headers, timeout=10)
        
        resultado = {'ip': ip, 'estado': 'desconocido', 'mensaje': '', 'maliciosos': 0}
        
        if respuesta.status_code == 200:
            datos = respuesta.json()
            stats = datos['data']['attributes']['last_analysis_stats']
            maliciosos = stats['malicious']
            sospechosos = stats['suspicious']
            
            resultado['maliciosos'] = maliciosos
            
            if maliciosos > 0:
                resultado['estado'] = 'malicioso'
                resultado['mensaje'] = f"🚨 ALERTA: Detectada como MALICIOSA por {maliciosos} motores"
            elif sospechosos > 0:
                resultado['estado'] = 'sospechoso'
                resultado['mensaje'] = f"⚠️ AVISO: Marcada como sospechosa ({sospechosos} motores)"
            else:
                resultado['estado'] = 'limpio'
                resultado['mensaje'] = "✅ Limpia (0 detecciones)"
                
        elif respuesta.status_code == 401:
            resultado['mensaje'] = "❌ Error: API Key inválida"
        else:
            resultado['mensaje'] = f"❓ Estado desconocido (Código {respuesta.status_code})"
        
        cache_global.set(cache_key, resultado)
        return resultado
        
    except requests.exceptions.Timeout:
        logger.warning(f"⏱️  Timeout consultando {ip}")
        return {'ip': ip, 'estado': 'timeout', 'mensaje': 'Timeout', 'maliciosos': 0}
    except Exception as e:
        logger.error(f"Error consultando VirusTotal para {ip}: {e}")
        return {'ip': ip, 'estado': 'error', 'mensaje': f'Error: {str(e)}', 'maliciosos': 0}

def extraer_ips_archivo(archivo: str) -> Set[str]:
    """Extrae IPs de un solo archivo."""
    ips = set()
    contenido = leer_archivo_completo(archivo)
    if contenido:
        encontradas = re.findall(REGEX_IP, contenido)
        for ip in encontradas:
            if not es_ip_privada(ip):
                ips.add(ip)
                logger.debug(f"🔍 IP encontrada: {ip} en {archivo}")
    return ips

def extraer_ips(ruta_proyecto: str) -> Set[str]:
    """Extrae todas las IPs públicas encontradas en archivos."""
    ips_encontradas = set()
    
    archivos = obtener_archivos_proyecto(ruta_proyecto, EXTENSIONES_VALIDAS)
    
    with ThreadPoolExecutor() as executor:
        futuros = [executor.submit(extraer_ips_archivo, archivo) for archivo in archivos]
        for futuro in as_completed(futuros):
            ips = futuro.result()
            if ips:
                ips_encontradas.update(ips)
    
    return ips_encontradas

async def escanear_ips_async(ips: List[str], api_key: str) -> List[Dict]:
    """Orquesta las llamadas asíncronas a VirusTotal."""
    sem = asyncio.Semaphore(4) # Controlamos el rate limit con un semáforo
    async with aiohttp.ClientSession() as session:
        tareas = [consultar_virustotal_async(ip, api_key, session, sem) for ip in ips]
        return await asyncio.gather(*tareas)

def analizar(ruta_proyecto: str) -> ResultadoAnalisis:
    """Función principal que llama main.py."""
    
    if not validar_ruta(ruta_proyecto):
        return ResultadoAnalisis('threat_intel', False, "Error: ruta no válida")
    
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        logger.warning("Falta configurar variable VT_API_KEY")
        return ResultadoAnalisis('threat_intel', False, "⚠️ Módulo omitido: Falta configurar VT_API_KEY.")
    
    logger.info("🌐 Iniciando análisis de Threat Intel...")
    
    logger.info("🔍 Extrayendo IPs del proyecto...")
    ips_encontradas = extraer_ips(ruta_proyecto)
    
    if not ips_encontradas:
        logger.info("No se encontraron IPs públicas")
        return ResultadoAnalisis('threat_intel', True, "✅ No se encontraron IPs públicas para analizar.", [])
        
    hallazgos = []
    ips_maliciosas = 0
    
    ips_lista = list(ips_encontradas)
    
    # Ejecución concurrente si aiohttp está disponible
    if aiohttp:
        resultados = asyncio.run(escanear_ips_async(ips_lista, api_key))
    else:
        logger.warning("aiohttp no instalado. Ejecutando secuencialmente (lento).")
        resultados = []
        for idx, ip in enumerate(ips_lista, 1):
            resultados.append(consultar_virustotal(ip, api_key))
            if idx < len(ips_lista):
                time.sleep(4)

    for resultado in resultados:
        ip = resultado['ip']
        
        if resultado['estado'] in ['malicioso', 'sospechoso']:
            hallazgos.append({
                'tipo': 'IP Reputación',
                'descripcion': f"{ip}: {resultado['mensaje']}",
                'severidad': 'alto' if resultado['estado'] == 'malicioso' else 'medio',
                'linea': 0,
                'archivo': ip
            })
            ips_maliciosas += 1
            
    resultado_msg = f"\n🌐 Módulo: THREAT INTEL - Reputación\n{'='*50}\n✅ Se analizaron {len(ips_encontradas)} IPs únicas\n"
    
    if hallazgos:
        resultado_msg += f"\n⚠️ Se detectaron {len(hallazgos)} IPs maliciosas/sospechosas:\n"
        for h in hallazgos:
            resultado_msg += f"  🌐 {h['descripcion']}\n"
    else:
        resultado_msg += "\n✅ Todas las IPs están limpias en VirusTotal"
    
    analisis = ResultadoAnalisis('threat_intel', True, resultado_msg, hallazgos)

    if ips_maliciosas > 0:
        logger.warning(f"Detectadas {ips_maliciosas} IPs maliciosas")
    
    return analisis