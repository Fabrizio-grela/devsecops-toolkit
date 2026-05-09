"""
Módulo Leaks & Secrets
Detecta credenciales, claves de API y otros secretos hardcodeados.
Con sugerencias automáticas de remediación.
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
from utils import logger, validar_ruta, obtener_archivos_proyecto, ResultadoAnalisis, EXTENSIONES_VALIDAS, leer_lineas_archivo

try:
    import ai_handler
except ImportError:
    ai_handler = None

# Patrones de detección de secretos
REGLAS = {
    "Token de AWS": re.compile(r"(AKIA|ASIA|AIDA|AROA|AIPA|ANPA)[0-9A-Z]{16}"),
    "Clave Privada": re.compile(r"-----BEGIN .* PRIVATE KEY-----"),
    "Contraseña Hardcodeada": re.compile(r"(?i)(password|passwd|pwd|secret)\s*[:=]\s*['\"]?[^'\"\s]{4,}['\"]?"),
    "API Key Genérica": re.compile(r"(?i)(api_key|apikey|token|auth|client_secret)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?"),
    "Token GitHub": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "Token Stripe": re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}"),
    "URI de Base de Datos": re.compile(r"(?i)(mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9_\.\-]+:[0-9]+"),
    "Token JWT": re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}")
}

def scan_archivo(ruta_archivo: str) -> List[Dict]:
    """Escanea un archivo en busca de secretos."""
    hallazgos = []

    lineas = leer_lineas_archivo(ruta_archivo)
    if not lineas:
        return hallazgos

    for num_linea, linea in enumerate(lineas, 1):
        for nombre_regla, patron in REGLAS.items():
            if patron.search(linea):
                codigo_limpio = linea.strip()
                
                # Ignorar palabras clave de pruebas para evitar falsos positivos
                if any(falso in codigo_limpio.lower() for falso in ['test', 'example', 'dummy', '1234', 'xxxx', 'placeholder']):
                    continue

                hallazgos.append({
                    'tipo': nombre_regla,
                    'linea': num_linea,
                    'descripcion': f"Posible {nombre_regla} detectada",
                    'archivo': ruta_archivo,
                    'codigo': linea.strip()[:80],
                    'severidad': 'critico'
                })
                logger.debug(f"🔐 {nombre_regla} en {ruta_archivo}:{num_linea}")
    
    return hallazgos

def obtener_remediacion(tipo_secret: str, codigo: str) -> Optional[Dict]:
    """Obtiene sugerencia de remediación automática."""
    if not ai_handler:
        return None
    
    try:
        logger.debug(f"🤖 Generando remediación para {tipo_secret}...")
        resultado = ai_handler.get_remediation(
            f"Secreto expuesto: {tipo_secret}",
            codigo,
            "python"
        )
        return resultado
    except Exception as e:
        logger.warning(f"Error obteniendo remediación: {e}")
        return None

def analizar(ruta_proyecto: str) -> ResultadoAnalisis:
    """Función principal que llama main.py."""
    
    if not validar_ruta(ruta_proyecto):
        return ResultadoAnalisis(
            modulo='leaks',
            exito=False,
            mensaje="Error: ruta no válida"
        )
    
    logger.info("🔑 Iniciando análisis de Secrets & Leaks...")
    
    hallazgos_totales = []
    archivos_escaneados = 0
    
    archivos = obtener_archivos_proyecto(ruta_proyecto, EXTENSIONES_VALIDAS)
    
    with ThreadPoolExecutor() as executor:
        futuros = [executor.submit(scan_archivo, archivo) for archivo in archivos]
        for futuro in as_completed(futuros):
            hallazgos = futuro.result()
            if hallazgos:
                hallazgos_totales.extend(hallazgos)
            archivos_escaneados += 1
    
    resultado_msg = f"\n🔍 Módulo: LEAKS - Detección de Secretos\n"
    resultado_msg += f"{'='*50}\n"
    
    if not hallazgos_totales:
        resultado_msg += f"✅ No se encontraron secretos en {archivos_escaneados} archivos\n"
        logger.info(resultado_msg)
        return ResultadoAnalisis(
            modulo='leaks',
            exito=True,
            mensaje=resultado_msg,
            hallazgos=[]
        )
    
    resultado_msg += f"⚠️ Se encontraron {len(hallazgos_totales)} posibles secretos:\n"
    for idx, hallazgo in enumerate(hallazgos_totales, 1):
        resultado_msg += f"  {idx}. 🚨 [{hallazgo['tipo']}] {hallazgo['archivo']} (Línea {hallazgo['linea']})\n"
        
        # Obtener remediación automática (limitado a los primeros 5 para no saturar la API)
        if ai_handler and idx <= 5:
            remediacion = obtener_remediacion(hallazgo['tipo'], hallazgo['codigo'])
            if remediacion and remediacion.get('exito'):
                resultado_msg += f"     ✅ Solución: {remediacion['solucion']}\n"
                hallazgo['remediacion'] = remediacion
    
    logger.warning(f"Detectados {len(hallazgos_totales)} hallazgos")
    
    return ResultadoAnalisis(
        modulo='leaks',
        exito=True,
        mensaje=resultado_msg,
        hallazgos=hallazgos_totales
    )