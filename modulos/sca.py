"""
Módulo SCA (Software Composition Analysis)
Detecta vulnerabilidades en dependencias (CVEs, paquetes desactualizados).
"""

import os
import re
import requests
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import logger, validar_ruta, leer_lineas_archivo, leer_archivo_completo, ResultadoAnalisis, cargar_devsecignore, IGNORAR_CARPETAS_COMUN

def consultar_osv_batch(tareas_paquetes: List[Tuple[str, str, str, str]]) -> List[Dict]:
    """Consulta la API de OSV en bloque (Batch Query) para máximo rendimiento."""
    url = "https://api.osv.dev/v1/querybatch"
    hallazgos = []
    
    chunk_size = 100
    for i in range(0, len(tareas_paquetes), chunk_size):
        chunk = tareas_paquetes[i:i + chunk_size]
        queries = []
        
        for paquete, version, _, ecosistema in chunk:
            query = {"package": {"name": paquete, "ecosystem": ecosistema}}
            if version and version != "latest":
                query["version"] = version
            queries.append(query)
            
        try:
            logger.debug(f"📡 Consultando OSV Batch: {len(chunk)} paquetes...")
            respuesta = requests.post(url, json={"queries": queries}, timeout=15)
            
            if respuesta.status_code == 200:
                resultados = respuesta.json().get("results", [])
                for idx, res in enumerate(resultados):
                    if "vulns" in res and res["vulns"]:
                        paquete, version, ruta_completa, ecosistema = chunk[idx]
                        cve_id = res["vulns"][0].get("id", "CVE-DESCONOCIDO")
                        hallazgos.append({
                            'tipo': 'CVE/Vulnerabilidad',
                            'descripcion': f"[{ecosistema}] {paquete} v{version} es vulnerable",
                            'severidad': 'alto',
                            'linea': 0,
                            'archivo': ruta_completa,
                            'cve': cve_id
                        })
        except Exception as e:
            logger.warning(f"Error en consulta OSV Batch: {e}")
            
    return hallazgos

def parsear_requirements(ruta_archivo: str) -> List[Tuple[str, str]]:
    """Extrae paquetes y versiones de requirements.txt."""
    paquetes = []
    lineas = leer_lineas_archivo(ruta_archivo)
    
    if not lineas:
        return paquetes
    
    for linea in lineas:
        linea = linea.strip()
        
        if not linea or linea.startswith('#'):
            continue
        
        # Extrae nombre y versión (soporta ==, >=, <=, >, <)
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:==|>=|<=|>|<)?([0-9\.]+)?", linea)
        if match:
            nombre = match.group(1)
            version = match.group(2) or "latest"
            paquetes.append((nombre, version))
    
    return paquetes

def parsear_package_json(ruta_archivo: str) -> List[Tuple[str, str]]:
    """Extrae paquetes y versiones de package.json."""
    paquetes = []
    contenido = leer_archivo_completo(ruta_archivo)
    
    if not contenido:
        return paquetes
    
    try:
        data = json.loads(contenido)
        deps = {}
        if "dependencies" in data:
            deps.update(data["dependencies"])
        if "devDependencies" in data:
            deps.update(data["devDependencies"])
            
        for nombre, version in deps.items():
            # Limpiar versión (quitar ^, ~, >=, etc.)
            version_limpia = re.sub(r'[~^>=<]', '', version).strip()
            # Toma la primera parte si hay espacios (ej. "1.2.3 || 2.0.0")
            version_limpia = version_limpia.split(' ')[0]
            if not version_limpia or version_limpia == '*':
                version_limpia = "latest"
            paquetes.append((nombre, version_limpia))
    except Exception as e:
        logger.debug(f"Error parseando {ruta_archivo}: {e}")
        
    return paquetes

def parsear_pom_xml(ruta_archivo: str) -> List[Tuple[str, str]]:
    """Extrae paquetes y versiones de pom.xml (Java/Maven)."""
    paquetes = []
    try:
        tree = ET.parse(ruta_archivo)
        root = tree.getroot()
        
        # Iterar sobre todos los elementos ignorando su namespace ({url}tag)
        for elem in root.iter():
            if elem.tag.endswith('dependency'):
                group_id = None
                artifact_id = None
                version = None
                for child in elem:
                    if child.tag.endswith('groupId'): group_id = child.text
                    elif child.tag.endswith('artifactId'): artifact_id = child.text
                    elif child.tag.endswith('version'): version = child.text
                
                if group_id and artifact_id and version:
                    version = version.strip()
                    # Ignoramos las versiones interpoladas como ${spring.version}
                    if not version.startswith('${'):
                        paquetes.append((f"{group_id}:{artifact_id}", version))
    except Exception as e:
        logger.debug(f"Error parseando {ruta_archivo}: {e}")
        
    return paquetes

def parsear_go_mod(ruta_archivo: str) -> List[Tuple[str, str]]:
    """Extrae paquetes y versiones de go.mod (GoLang)."""
    paquetes = []
    lineas = leer_lineas_archivo(ruta_archivo)
    
    if not lineas:
        return paquetes
    
    for linea in lineas:
        linea_strip = linea.strip()
        
        # Quitar la palabra 'require ' si la dependencia está en la misma línea
        if linea_strip.startswith('require '):
            linea_strip = linea_strip[8:].strip()
            
        # Busca un módulo y una versión típica de Go (ej: github.com/gin-gonic/gin v1.7.4)
        match = re.match(r"^([a-zA-Z0-9\.\-\/]+)\s+(v[0-9a-zA-Z\.\-\+]+)", linea_strip)
        if match:
            paquetes.append((match.group(1), match.group(2)))
            
    return paquetes

def analizar(ruta_proyecto: str) -> ResultadoAnalisis:
    """Función principal que llama main.py."""
    
    if not validar_ruta(ruta_proyecto):
        return ResultadoAnalisis('sca', False, "Error: ruta no válida")
    
    logger.info("🐛 Iniciando análisis SCA...")
    
    hallazgos = []
    archivos_analizados = 0
    
    ignorados_totales = IGNORAR_CARPETAS_COMUN | cargar_devsecignore(ruta_proyecto)
    
    tareas_paquetes = []
    
    for raiz, directorios, archivos in os.walk(ruta_proyecto):
        directorios[:] = [d for d in directorios if d not in ignorados_totales]
        
        if "requirements.txt" in archivos and "requirements.txt" not in ignorados_totales:
            ruta_completa = os.path.join(raiz, "requirements.txt")
            archivos_analizados += 1
            
            logger.info(f"Analizando: {ruta_completa}")
            paquetes = parsear_requirements(ruta_completa)
            
            for paquete, version in paquetes:
                tareas_paquetes.append((paquete, version, ruta_completa, "PyPI"))
                
        if "package.json" in archivos and "package.json" not in ignorados_totales:
            ruta_completa = os.path.join(raiz, "package.json")
            archivos_analizados += 1
            
            logger.info(f"Analizando: {ruta_completa}")
            paquetes = parsear_package_json(ruta_completa)
            
            for paquete, version in paquetes:
                tareas_paquetes.append((paquete, version, ruta_completa, "npm"))
                
        if "pom.xml" in archivos and "pom.xml" not in ignorados_totales:
            ruta_completa = os.path.join(raiz, "pom.xml")
            archivos_analizados += 1
            
            logger.info(f"Analizando: {ruta_completa}")
            paquetes = parsear_pom_xml(ruta_completa)
            
            for paquete, version in paquetes:
                tareas_paquetes.append((paquete, version, ruta_completa, "Maven"))
                
        if "go.mod" in archivos and "go.mod" not in ignorados_totales:
            ruta_completa = os.path.join(raiz, "go.mod")
            archivos_analizados += 1
            
            logger.info(f"Analizando: {ruta_completa}")
            paquetes = parsear_go_mod(ruta_completa)
            
            for paquete, version in paquetes:
                tareas_paquetes.append((paquete, version, ruta_completa, "Go"))
                
    if tareas_paquetes:
        hallazgos.extend(consultar_osv_batch(tareas_paquetes))
    
    if not hallazgos:
        logger.info(f"✅ No se encontraron vulnerabilidades en {archivos_analizados} archivos de dependencias")
        return ResultadoAnalisis('sca', True, f"✅ Análisis completado: Dependencias seguras en {archivos_analizados} archivo(s)", [])
    
    resultado_msg = f"\n🐛 Módulo: SCA - Análisis de Dependencias\n"
    resultado_msg += f"{'='*50}\n"
    resultado_msg += f"⚠️ Se detectaron {len(hallazgos)} dependencias vulnerables:\n"
    
    for h in hallazgos:
        resultado_msg += f"  🐛 [{h['cve']}] {h['descripcion']} en {h['archivo']}\n"
        
    analisis = ResultadoAnalisis('sca', True, resultado_msg, hallazgos)
    
    logger.warning(f"Detectadas {len(hallazgos)} vulnerabilidades en dependencias")
    
    return analisis