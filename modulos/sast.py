"""
Módulo SAST (Static Application Security Testing)
Análisis de código vulnerable en múltiples lenguajes.
Detecta: RCE, XSS, SQL Injection, Buffer Overflow, etc.
Con remediación automática por IA.
"""

import re
import os
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import logger, validar_ruta, obtener_archivos_proyecto, EXTENSIONES_CODIGOS, ResultadoAnalisis, leer_lineas_archivo

try:
    import ai_handler
except ImportError:
    ai_handler = None

# Expresión regular precompilada para ignorar falsos positivos
IGNORE_EVAL_PATTERN = re.compile(r'["\'].*eval\(.*["\']')

# Reglas multi-lenguaje (Python, JS, Java, PHP, C/C++)
RULES = {
    '.py': [
        (re.compile(r'eval\('), 'Uso de eval() - Riesgo de RCE', 'critico', 'python'),
        (re.compile(r'exec\('), 'Uso de exec() - Riesgo de RCE', 'critico', 'python'),
        (re.compile(r'os\.system\('), 'Inyección de comandos', 'alto', 'python'),
        (re.compile(r'subprocess\.(call|run|Popen)\s*\(\s*\[?["\'](?!.*\[)'), 'Ejecución de comandos insegura', 'alto', 'python'),
        (re.compile(r'pickle\.load\('), 'Deserialización insegura', 'alto', 'python'),
    ],
    '.js': [
        (re.compile(r'eval\('), 'Inyección de código JavaScript', 'critico', 'javascript'),
        (re.compile(r'innerHTML\s*='), 'Riesgo crítico de XSS', 'critico', 'javascript'),
        (re.compile(r'document\.write\('), 'Riesgo de XSS', 'alto', 'javascript'),
        (re.compile(r'dangerouslySetInnerHTML'), 'Uso de dangerouslySetInnerHTML (React)', 'alto', 'javascript'),
    ],
    '.java': [
        (re.compile(r'Runtime\.getRuntime\(\)\.exec\('), 'Ejecución de comandos - RCE', 'critico', 'java'),
        (re.compile(r'Statement\.executeQuery\('), 'Posible SQL Injection', 'alto', 'java'),
        (re.compile(r'String\.format.*sql'), 'Posible SQL Injection con format', 'alto', 'java'),
    ],
    '.php': [
        (re.compile(r'eval\('), 'Riesgo crítico de RCE', 'critico', 'php'),
        (re.compile(r'include\(\$_GET'), 'LFI/RFI Detectado', 'critico', 'php'),
        (re.compile(r'require\(\$_'), 'Remote Include detectado', 'critico', 'php'),
        (re.compile(r'system\('), 'Ejecución de comandos insegura', 'alto', 'php'),
        (re.compile(r'passthru\('), 'Ejecución de comandos', 'alto', 'php'),
    ],
    '.c': [
        (re.compile(r'gets\('), 'Buffer Overflow - gets() prohibido', 'critico', 'c'),
        (re.compile(r'strcpy\('), 'Buffer Overflow con strcpy', 'alto', 'c'),
        (re.compile(r'sprintf\('), 'Posible Buffer Overflow', 'medio', 'c'),
    ],
    '.cpp': [
        (re.compile(r'strcpy\('), 'Buffer Overflow con strcpy', 'alto', 'cpp'),
        (re.compile(r'memcpy\('), 'Posible Buffer Overflow con memcpy', 'medio', 'cpp'),
    ]
}

# Enlazar extensiones adicionales a las reglas de JavaScript
RULES['.ts'] = RULES['.js']
RULES['.tsx'] = RULES['.js']
RULES['.jsx'] = RULES['.js']

def scan_sast(ruta_archivo: str) -> List[Dict]:
    """Escanea un archivo en busca de vulnerabilidades."""
    vulnerabilidades = []
    ext = os.path.splitext(ruta_archivo)[1].lower()
    
    if ext not in RULES:
        return vulnerabilidades
    
    lineas = leer_lineas_archivo(ruta_archivo)
    if not lineas:
        return vulnerabilidades

    for num, linea in enumerate(lineas, 1):
        linea_strip = linea.strip()
        
        # Ignorar comentarios para evitar falsos positivos
        if linea_strip.startswith('#') or linea_strip.startswith('//'):
            continue
            
        # Ignorar líneas marcadas explícitamente como seguras por el desarrollador
        if linea_strip.endswith('# nosec') or linea_strip.endswith('# devsec:ignore'):
            continue
        
        # Ignorar logs, tests y strings comunes que causan falsos positivos
        if linea_strip.startswith(('print(', 'logger.', 'assert ', '"""', "'''", 'r1.', 'resultado')):
            continue
        if IGNORE_EVAL_PATTERN.search(linea_strip):
            continue

        for patron_regex, mensaje, severidad, lenguaje in RULES[ext]:
            if patron_regex.search(linea):
                vulnerabilidades.append({
                    'tipo': ext.upper().replace('.', ''),
                    'descripcion': mensaje,
                    'linea': num,
                    'codigo': linea.strip()[:80],
                    'severidad': severidad,
                    'archivo': ruta_archivo,
                    'lenguaje': lenguaje
                })
                logger.debug(f"🔴 [{ext}] {mensaje} en {ruta_archivo}:{num}")
    
    return vulnerabilidades

def obtener_remediacion(tipo_vuln: str, codigo: str, lenguaje: str) -> Optional[Dict]:
    """Obtiene remediación automática con IA."""
    if not ai_handler:
        return None
    
    try:
        logger.debug(f"🤖 Generando remediación para {tipo_vuln}...")
        resultado = ai_handler.get_remediation(tipo_vuln, codigo, lenguaje)
        return resultado
    except Exception as e:
        logger.warning(f"Error obteniendo remediación: {e}")
        return None

def analizar(ruta: str) -> ResultadoAnalisis:
    """Función principal que llama main.py."""
    
    if not validar_ruta(ruta):
        return ResultadoAnalisis('sast', False, "Error: ruta no válida")
    
    logger.info("☢️  Iniciando análisis SAST...")
    
    resultados_totales = []
    archivos_analizados = 0
    
    # Obtiene todos los archivos de código en una sola pasada de disco
    archivos = obtener_archivos_proyecto(ruta, EXTENSIONES_CODIGOS)
    
    with ThreadPoolExecutor() as executor:
        futuros = [executor.submit(scan_sast, archivo) for archivo in archivos]
        for futuro in as_completed(futuros):
            res = futuro.result()
            if res:
                resultados_totales.extend(res)
            archivos_analizados += 1
    
    if not resultados_totales:
        logger.info(f"✅ No se detectaron vulnerabilidades en {archivos_analizados} archivos")
        return ResultadoAnalisis('sast', True, f"✅ Análisis completado: No se detectaron vulnerabilidades en {archivos_analizados} archivos", [])
    
    resultado_msg = f"\n☢️ Módulo: SAST - Análisis Estático\n"
    resultado_msg += f"{'='*50}\n"
    resultado_msg += f"⚠️ Se detectaron {len(resultados_totales)} vulnerabilidades potenciales:\n"
    
    por_severidad = {}
    for v in resultados_totales:
        sev = v['severidad']
        if sev not in por_severidad:
            por_severidad[sev] = 0
        por_severidad[sev] += 1
    
    for sev, count in sorted(por_severidad.items(), reverse=True):
        resultado_msg += f"  • {sev.upper()}: {count}\n"
    
    resultado_msg += "\n"
    
    analisis = ResultadoAnalisis('sast', True, "", resultados_totales)
    
    for idx, v in enumerate(resultados_totales, 1):
        resultado_msg += f"  {idx}. 🔴 [{v['severidad'].upper()}] {v['descripcion']} en {v['archivo']} (Línea {v['linea']})\n"
        
        # Solo pide IA para las primeras 5 vulnerabilidades severas (evita demorar horas)
        if ai_handler and v['severidad'] in ['critico', 'alto'] and idx <= 5:
            remediacion = obtener_remediacion(v['descripcion'], v['codigo'], v['lenguaje'])
            if remediacion and remediacion.get('exito'):
                resultado_msg += f"     ✅ Solución IA: {remediacion['solucion']}\n"
                v['remediacion'] = remediacion
    
    analisis.mensaje = resultado_msg
    logger.warning(f"Detectadas {len(resultados_totales)} vulnerabilidades")
    
    return analisis