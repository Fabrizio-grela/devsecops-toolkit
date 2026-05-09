"""
Módulo IaC Scanner (Infrastructure as Code)
Audita configuraciones de infraestructura (Dockerfiles, Kubernetes, Terraform, etc).
"""

import os
import re
import json
import subprocess
from typing import List, Dict, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import logger, validar_ruta, leer_lineas_archivo, ResultadoAnalisis, cargar_devsecignore, IGNORAR_CARPETAS_COMUN

try:
    import ai_handler
except ImportError:
    ai_handler = None

# Reglas específicas para detectar malas prácticas en Docker
REGLAS_IAC = {
    "Imagen base sin versionar": {
        "patron": re.compile(r"(?i)^FROM\s+[a-zA-Z0-9_\-\/]+(:latest)?\s*$"),
        "mensaje": "Usa 'latest' o sin versión especificada",
        "severidad": "medio"
    },
    "Puerto SSH expuesto": {
        "patron": re.compile(r"(?i)^EXPOSE\s+.*?\b22\b"),
        "mensaje": "Puerto SSH (22) potencialmente expuesto",
        "severidad": "alto"
    },
    "Secretos en variables de entorno": {
        "patron": re.compile(r"(?i)^(ENV|ARG)\s+.*(PASSWORD|SECRET|TOKEN|API_KEY|KEY|PASS)\s*="),
        "mensaje": "Secretos potenciales en variables de entorno",
        "severidad": "critico"
    },
    "Root user": {
        "patron": re.compile(r"(?i)^USER\s+root"),
        "mensaje": "Contenedor ejecutándose como root",
        "severidad": "alto"
    },
}

# Reglas para Kubernetes
REGLAS_K8S = {
    "Contenedor Privilegiado": {
        "patron": re.compile(r"(?i)privileged:\s*true"),
        "mensaje": "El contenedor se ejecuta en modo privilegiado (acceso total al nodo)",
        "severidad": "critico"
    },
    "Escalamiento de Privilegios": {
        "patron": re.compile(r"(?i)allowPrivilegeEscalation:\s*true"),
        "mensaje": "El contenedor permite escalamiento de privilegios",
        "severidad": "alto"
    },
    "Ejecución como Root": {
        "patron": re.compile(r"(?i)runAsNonRoot:\s*false"),
        "mensaje": "El pod permite la ejecución de contenedores como usuario root",
        "severidad": "alto"
    },
    "Red del Host Expuesta": {
        "patron": re.compile(r"(?i)hostNetwork:\s*true"),
        "mensaje": "El pod tiene acceso directo a la red del nodo anfitrión",
        "severidad": "critico"
    },
    "PID del Host Expuesto": {
        "patron": re.compile(r"(?i)hostPID:\s*true"),
        "mensaje": "El pod tiene acceso al espacio de procesos del host",
        "severidad": "critico"
    },
    "Imagen sin versionar (K8s)": {
        "patron": re.compile(r"(?i)image:\s+[a-zA-Z0-9_\-\/]+(:latest)?\s*$"),
        "mensaje": "Uso de la etiqueta 'latest' o sin versión en contenedores",
        "severidad": "medio"
    }
}

# Reglas para Terraform
REGLAS_TERRAFORM = {
    "Security Group Abierto": {
        "patron": re.compile(r"cidr_blocks\s*=\s*\[\s*[\"']0\.0\.0\.0/0[\"']\s*\]"),
        "mensaje": "Regla de red abierta a todo internet (0.0.0.0/0)",
        "severidad": "alto"
    },
    "S3 sin restricción pública": {
        "patron": re.compile(r"(?i)acl\s*=\s*[\"']public-read[\"']"),
        "mensaje": "Bucket S3 configurado con acceso de lectura público",
        "severidad": "alto"
    }
}

def scan_dockerfile(ruta_archivo: str) -> List[Dict]:
    """Escanea un Dockerfile en busca de configuraciones inseguras."""
    hallazgos = []
    
    lineas = leer_lineas_archivo(ruta_archivo)
    if not lineas:
        return hallazgos
    
    tiene_usuario_no_root = False
    
    for num_linea, linea in enumerate(lineas, 1):
        linea_strip = linea.strip()
        
        if linea_strip.upper().startswith("USER ") and "root" not in linea_strip.lower():
            tiene_usuario_no_root = True
        
        for nombre_regla, info_regla in REGLAS_IAC.items():
            if info_regla['patron'].search(linea_strip):
                hallazgos.append({
                    'tipo': nombre_regla,
                    'descripcion': info_regla['mensaje'],
                    'severidad': info_regla['severidad'],
                    'linea': num_linea,
                    'archivo': ruta_archivo,
                    'codigo': linea_strip
                })
                logger.debug(f"🏗️  {nombre_regla} en {ruta_archivo}:{num_linea}")
    
    # Análisis de contexto: Detecta extensiones .dev o .prod y verifica usuario
    nombre_base = os.path.basename(ruta_archivo)
    if (nombre_base == "Dockerfile" or nombre_base.startswith("Dockerfile.")) and not tiene_usuario_no_root:
        hallazgos.append({
            'tipo': 'Contenedor corre con privilegios ROOT',
            'descripcion': 'No se especificó ningún USER - ejecutará como root',
            'severidad': 'alto',
            'linea': 0,
            'archivo': ruta_archivo,
            'codigo': 'Falta instrucción USER'
        })
        logger.debug(f"🏗️  Contenedor root en {ruta_archivo}")
    
    return hallazgos

def scan_generico_iac(ruta_archivo: str, reglas: Dict[str, Any]) -> List[Dict]:
    """Escanea archivos YAML/TF usando un set de reglas provisto."""
    hallazgos = []
    lineas = leer_lineas_archivo(ruta_archivo)
    if not lineas:
        return hallazgos
        
    for num_linea, linea in enumerate(lineas, 1):
        linea_strip = linea.strip()
        for nombre_regla, info_regla in reglas.items():
            if info_regla['patron'].search(linea_strip):
                hallazgos.append({
                    'tipo': nombre_regla,
                    'descripcion': info_regla['mensaje'],
                    'severidad': info_regla['severidad'],
                    'linea': num_linea,
                    'archivo': ruta_archivo,
                    'codigo': linea_strip
                })
                logger.debug(f"🏗️  {nombre_regla} en {ruta_archivo}:{num_linea}")
    return hallazgos

def obtener_remediacion(tipo_problema: str, codigo: str) -> Optional[Dict]:
    """Obtiene sugerencia de remediación automática."""
    if not ai_handler or not codigo:
        return None
    try:
        logger.debug(f"🤖 Generando remediación IaC para {tipo_problema}...")
        return ai_handler.get_remediation(f"Inseguridad IaC: {tipo_problema}", codigo, "dockerfile")
    except Exception as e:
        logger.warning(f"Error obteniendo remediación IaC: {e}")
        return None

def analizar_archivo_iac(ruta_completa: str, archivo: str) -> List[Dict]:
    """Escanea un archivo individual y retorna sus hallazgos."""
    hallazgos_trivy = scan_con_trivy(ruta_completa)
    if hallazgos_trivy is not None:
        return hallazgos_trivy
        
    if archivo == "Dockerfile" or archivo.startswith("Dockerfile."):
        return scan_dockerfile(ruta_completa)
    elif archivo.endswith('.tf'):
        return scan_generico_iac(ruta_completa, REGLAS_TERRAFORM)
    elif archivo.endswith(('.yml', '.yaml')):
        return scan_generico_iac(ruta_completa, REGLAS_K8S)
    return []

def scan_con_trivy(ruta_archivo: str) -> Optional[List[Dict]]:
    """Intenta usar Trivy CLI para un escaneo profundo de IaC."""
    hallazgos = []
    try:
        logger.debug(f"Intentando escaneo avanzado con Trivy en {ruta_archivo}")
        resultado = subprocess.run(
            ['trivy', 'config', '--format', 'json', '--quiet', ruta_archivo],
            capture_output=True, text=True, check=False
        )
        
        if resultado.stdout:
            datos = json.loads(resultado.stdout)
            if 'Results' in datos:
                for res in datos['Results']:
                    if 'Misconfigurations' in res:
                        for misc in res['Misconfigurations']:
                            severidad = misc.get('Severity', 'MEDIUM').lower()
                            if severidad == 'high': severidad = 'alto'
                            elif severidad == 'critical': severidad = 'critico'
                            elif severidad == 'medium': severidad = 'medio'
                            elif severidad == 'low': severidad = 'bajo'
                            
                            hallazgos.append({
                                'tipo': f"Trivy: {misc.get('Type', 'Misconfig')}",
                                'descripcion': f"{misc.get('Title', '')} - {misc.get('Message', '')}",
                                'severidad': severidad,
                                'linea': misc.get('CauseMetadata', {}).get('StartLine', 0),
                                'archivo': ruta_archivo,
                                'codigo': f"ID de Regla: {misc.get('ID', 'N/A')}"
                            })
            return hallazgos
    except FileNotFoundError:
        return None # Trivy no está instalado en el sistema
    except Exception as e:
        logger.debug(f"Error parseando Trivy: {e}")
        return None

def analizar(ruta_proyecto: str) -> ResultadoAnalisis:
    """Función principal que llama main.py."""
    
    if not validar_ruta(ruta_proyecto):
        return ResultadoAnalisis('iac_scanner', False, "Error: ruta no válida")
    
    logger.info("🏗️  Iniciando análisis IaC...")
    
    hallazgos_totales = []
    archivos_escaneados = 0
    
    ignorados_totales = IGNORAR_CARPETAS_COMUN | cargar_devsecignore(ruta_proyecto)
    archivos_a_escanear = []
    
    for raiz, directorios, archivos in os.walk(ruta_proyecto):
        directorios[:] = [d for d in directorios
                         if d not in ignorados_totales and not d.endswith('.egg-info')]
        
        for archivo in archivos:
            if archivo in ignorados_totales:
                continue
            
            es_iac = archivo == "Dockerfile" or archivo.startswith("Dockerfile.") or archivo.endswith(('.tf', '.yml', '.yaml'))
            
            if es_iac:
                ruta_completa = os.path.join(raiz, archivo)
                archivos_a_escanear.append((ruta_completa, archivo))
                
    with ThreadPoolExecutor() as executor:
        futuros = [executor.submit(analizar_archivo_iac, r, a) for r, a in archivos_a_escanear]
        for futuro in as_completed(futuros):
            res = futuro.result()
            if res:
                hallazgos_totales.extend(res)
            archivos_escaneados += 1
    
    if not hallazgos_totales:
        msg = f"✅ Análisis completado: Infraestructura segura. {archivos_escaneados} archivo(s) auditado(s)"
        logger.info(f"✅ Infraestructura segura: {archivos_escaneados} archivos sin problemas")
        return ResultadoAnalisis('iac_scanner', True, msg, [])
    
    resultado_msg = f"\n🏗️ Módulo: IAC SCANNER - Infraestructura\n"
    resultado_msg += f"{'='*50}\n"
    resultado_msg += f"⚠️ Se detectaron {len(hallazgos_totales)} problemas de configuración:\n"
    
    por_severidad = {}
    for h in hallazgos_totales:
        sev = h['severidad']
        if sev not in por_severidad:
            por_severidad[sev] = 0
        por_severidad[sev] += 1
    
    for sev, count in sorted(por_severidad.items(), reverse=True):
        resultado_msg += f"  • {sev.upper()}: {count}\n"
    
    resultado_msg += "\n"
    
    analisis = ResultadoAnalisis('iac_scanner', True, "", hallazgos_totales)
    
    for idx, h in enumerate(hallazgos_totales, 1):
        resultado_msg += f"  {idx}. 🏗️  [{h['severidad'].upper()}] {h['tipo']}: {h['descripcion']} en {h['archivo']} (Línea {h['linea']})\n"
        
        # Solo pide IA para configuraciones severas (máximo 5)
        if ai_handler and h['severidad'] in ['critico', 'alto'] and idx <= 5:
            remediacion = obtener_remediacion(h['tipo'], h.get('codigo', ''))
            if remediacion and remediacion.get('exito'):
                resultado_msg += f"     ✅ Solución IA: {remediacion['solucion']}\n"
                h['remediacion'] = remediacion # Lo adjuntamos para el reporte HTML
    
    analisis.mensaje = resultado_msg
    logger.warning(f"Detectadas {len(hallazgos_totales)} configuraciones inseguras")
    
    return analisis