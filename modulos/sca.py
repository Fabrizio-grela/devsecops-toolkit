"""
Módulo SCA (Software Composition Analysis)
Detecta vulnerabilidades en dependencias (CVEs, paquetes desactualizados).
"""

import os
import re
import requests
from typing import List, Dict, Optional, Tuple
from utils import logger, validar_ruta, leer_lineas_archivo, cache_global, ResultadoAnalisis, cargar_devsecignore, IGNORAR_CARPETAS_COMUN

def consultar_osv(paquete: str, version: str) -> Optional[str]:
    """
    Consulta la API pública de vulnerabilidades (OSV).
    Retorna CVE ID si hay vulnerabilidad, None si está limpio.
    """
    
    # Intenta obtener del caché primero
    cache_key = f"osv_{paquete}_{version}"
    resultado_cache = cache_global.get(cache_key)
    if resultado_cache is not None:
        logger.debug(f"✓ Caché hit: {paquete} {version}")
        return resultado_cache
    
    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version,
        "package": {
            "name": paquete,
            "ecosystem": "PyPI" 
        }
    }
    
    try:
        logger.debug(f"📡 Consultando OSV: {paquete} {version}")
        respuesta = requests.post(url, json=payload, timeout=10)
        
        if respuesta.status_code == 200:
            data = respuesta.json()
            if "vulns" in data and data["vulns"]:
                cve_id = data["vulns"][0].get("id", "CVE-DESCONOCIDO")
                cache_global.set(cache_key, cve_id)
                logger.debug(f"🚨 Vulnerabilidad encontrada: {cve_id}")
                return cve_id
        
        # Si no hay vulnerabilidades, cachea como "limpio"
        cache_global.set(cache_key, None)
        return None
        
    except requests.exceptions.Timeout:
        logger.warning(f"⏱️  Timeout consultando {paquete}")
        return None
    except Exception as e:
        logger.warning(f"Error en OSV para {paquete}: {e}")
        return None

def parsear_requirements(ruta_archivo: str) -> List[Tuple[str, str]]:
    """Extrae paquetes y versiones de requirements.txt."""
    paquetes = []
    lineas = leer_lineas_archivo(ruta_archivo)
    
    if not lineas:
        return paquetes
    
    for linea in lineas:
        linea = linea.strip()
        
        # Ignora comentarios y líneas vacías
        if not linea or linea.startswith('#'):
            continue
        
        # Extrae nombre y versión (soporta ==, >=, <=, >, <)
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:==|>=|<=|>|<)?([0-9\.]+)?", linea)
        if match:
            nombre = match.group(1)
            version = match.group(2) or "latest"
            paquetes.append((nombre, version))
    
    return paquetes

def analizar(ruta_proyecto: str) -> ResultadoAnalisis:
    """Función principal que llama main.py."""
    
    if not validar_ruta(ruta_proyecto):
        return ResultadoAnalisis('sca', False, "Error: ruta no válida")
    
    logger.info("🐛 Iniciando análisis SCA...")
    
    hallazgos = []
    requirements_encontrados = 0
    
    ignorados_totales = IGNORAR_CARPETAS_COMUN | cargar_devsecignore(ruta_proyecto)
    
    # Busca todos los requirements.txt
    for raiz, directorios, archivos in os.walk(ruta_proyecto):
        directorios[:] = [d for d in directorios if d not in ignorados_totales]
        
        if "requirements.txt" in archivos and "requirements.txt" not in ignorados_totales:
            ruta_completa = os.path.join(raiz, "requirements.txt")
            requirements_encontrados += 1
            
            logger.info(f"Analizando: {ruta_completa}")
            paquetes = parsear_requirements(ruta_completa)
            
            for paquete, version in paquetes:
                cve = consultar_osv(paquete, version)
                if cve:
                    hallazgos.append({
                        'tipo': 'CVE/Vulnerabilidad',
                        'descripcion': f"{paquete} v{version} es vulnerable",
                        'severidad': 'alto',
                        'linea': 0,
                        'archivo': ruta_completa,
                        'cve': cve
                    })
    
    if not hallazgos:
        logger.info(f"✅ No se encontraron vulnerabilidades en {requirements_encontrados} requirements.txt")
        return ResultadoAnalisis('sca', True, f"✅ Análisis completado: Dependencias seguras en {requirements_encontrados} archivo(s)", [])
    
    resultado_msg = f"\n🐛 Módulo: SCA - Análisis de Dependencias\n"
    resultado_msg += f"{'='*50}\n"
    resultado_msg += f"⚠️ Se detectaron {len(hallazgos)} dependencias vulnerables:\n"
    
    for h in hallazgos:
        resultado_msg += f"  🐛 [{h['cve']}] {h['descripcion']} en {h['archivo']}\n"
        
    analisis = ResultadoAnalisis('sca', True, resultado_msg, hallazgos)
    
    logger.warning(f"Detectadas {len(hallazgos)} vulnerabilidades en dependencias")
    
    return analisis