"""
Módulo SAST (Static Application Security Testing)
Análisis de código vulnerable en múltiples lenguajes.
Detecta: RCE, XSS, SQL Injection, Buffer Overflow, etc.
Con remediación automática por IA.
"""

import re
import os
from typing import List, Dict, Optional, Set
from utils import logger, validar_ruta, obtener_archivos_por_tipo, EXTENSIONES_CODIGOS, ResultadoAnalisis

try:
    import ai_handler
except ImportError:
    ai_handler = None

# Reglas multi-lenguaje (Python, JS, Java, PHP, C/C++)
RULES = {
    '.py': [
        (r'eval\(', 'Uso de eval() - Riesgo de RCE', 'critico', 'python'),
        (r'exec\(', 'Uso de exec() - Riesgo de RCE', 'critico', 'python'),
        (r'os\.system\(', 'Inyección de comandos', 'alto', 'python'),
        (r'subprocess\.(call|run|Popen)\s*\(\s*\[?["\'](?!.*\[)', 'Ejecución de comandos insegura', 'alto', 'python'),
        (r'pickle\.load\(', 'Deserialización insegura', 'alto', 'python'),
    ],
    '.js': [
        (r'eval\(', 'Inyección de código JavaScript', 'critico', 'javascript'),
        (r'innerHTML\s*=', 'Riesgo crítico de XSS', 'critico', 'javascript'),
        (r'document\.write\(', 'Riesgo de XSS', 'alto', 'javascript'),
        (r'dangerouslySetInnerHTML', 'Uso de dangerouslySetInnerHTML (React)', 'alto', 'javascript'),
    ],
    '.java': [
        (r'Runtime\.getRuntime\(\)\.exec\(', 'Ejecución de comandos - RCE', 'critico', 'java'),
        (r'Statement\.executeQuery\(', 'Posible SQL Injection', 'alto', 'java'),
        (r'String\.format.*sql', 'Posible SQL Injection con format', 'alto', 'java'),
    ],
    '.php': [
        (r'eval\(', 'Riesgo crítico de RCE', 'critico', 'php'),
        (r'include\(\$_GET', 'LFI/RFI Detectado', 'critico', 'php'),
        (r'require\(\$_', 'Remote Include detectado', 'critico', 'php'),
        (r'system\(', 'Ejecución de comandos insegura', 'alto', 'php'),
        (r'passthru\(', 'Ejecución de comandos', 'alto', 'php'),
    ],
    '.c': [
        (r'gets\(', 'Buffer Overflow - gets() prohibido', 'critico', 'c'),
        (r'strcpy\(', 'Buffer Overflow con strcpy', 'alto', 'c'),
        (r'sprintf\(', 'Posible Buffer Overflow', 'medio', 'c'),
    ],
    '.cpp': [
        (r'strcpy\(', 'Buffer Overflow con strcpy', 'alto', 'cpp'),
        (r'memcpy\(', 'Posible Buffer Overflow con memcpy', 'medio', 'cpp'),
    ]
}

def scan_sast(ruta_archivo: str) -> List[Dict]:
    """Escanea un archivo en busca de vulnerabilidades."""
    vulnerabilidades = []
    ext = os.path.splitext(ruta_archivo)[1].lower()
    
    if ext not in RULES:
        return vulnerabilidades
    
    try:
        with open(ruta_archivo, 'r', encoding='utf-8', errors='ignore') as f:
            for num, linea in enumerate(f, 1):
                linea_strip = linea.strip()
                
                # Ignorar comentarios para evitar falsos positivos
                if linea_strip.startswith('#') or linea_strip.startswith('//'):
                    continue
                
                # Ignorar logs, tests y strings comunes que causan falsos positivos
                if linea_strip.startswith(('print(', 'logger.', 'assert ', '"""', "'''", 'r1.', 'resultado')):
                    continue
                if re.search(r'["\'].*eval\(.*["\']', linea_strip):
                    continue

                for patron, mensaje, severidad, lenguaje in RULES[ext]:
                    if re.search(patron, linea):
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
    except Exception as e:
        logger.warning(f"Error leyendo {ruta_archivo}: {e}")
    
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
    
    # Obtiene todos los archivos de código
    archivos = obtener_archivos_por_tipo(ruta, tipo="python")
    archivos.extend(obtener_archivos_por_tipo(ruta, tipo="javascript"))
    archivos.extend(obtener_archivos_por_tipo(ruta, tipo="java"))
    archivos.extend(obtener_archivos_por_tipo(ruta, tipo="php"))
    archivos.extend(obtener_archivos_por_tipo(ruta, tipo="c"))
    
    # Elimina duplicados
    archivos = list(set(archivos))
    
    for archivo in archivos:
        res = scan_sast(archivo)
        if res:
            resultados_totales.extend(res)
        archivos_analizados += 1
    
    if not resultados_totales:
        logger.info(f"✅ No se detectaron vulnerabilidades en {archivos_analizados} archivos")
        return ResultadoAnalisis('sast', True, f"✅ Análisis completado: No se detectaron vulnerabilidades en {archivos_analizados} archivos", [])
    
    resultado_msg = f"\n☢️ Módulo: SAST - Análisis Estático\n"
    resultado_msg += f"{'='*50}\n"
    resultado_msg += f"⚠️ Se detectaron {len(resultados_totales)} vulnerabilidades potenciales:\n"
    
    # Agrupa por severidad
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
    
    # Muestra todas las vulnerabilidades
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