"""
Utilidades compartidas del DevSecOps Toolkit
- Logger centralizado
- Funciones comunes
- Validaciones
- Caché básico
"""

import logging
import os
import sys
from pathlib import Path
from typing import List, Set, Optional, Dict, Any
from datetime import datetime
import json

# ==================== LOGGER ====================

def setup_logger(name: str = "devsec", level: int = logging.INFO) -> logging.Logger:
    """Configura logger estructurado para toda la aplicación."""
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Evita handlers duplicados
    if logger.handlers:
        return logger
    
    # Formato con timestamp y severidad
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Handler para consola
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

# Logger global
logger = setup_logger()

# ==================== VALIDACIONES ====================

def validar_ruta(ruta: str) -> bool:
    """Valida que la ruta exista y sea accesible."""
    if not ruta:
        logger.error("Ruta vacía proporcionada")
        return False
    
    if not os.path.exists(ruta):
        logger.error(f"La ruta '{ruta}' no existe")
        return False
    
    if not os.path.isdir(ruta):
        logger.error(f"'{ruta}' no es un directorio")
        return False
    
    return True

def validar_archivo(ruta: str, extensiones: tuple = None) -> bool:
    """Valida que el archivo exista y tenga la extensión correcta."""
    if not os.path.exists(ruta):
        logger.debug(f"Archivo no encontrado: {ruta}")
        return False
    
    if not os.path.isfile(ruta):
        logger.debug(f"'{ruta}' no es un archivo")
        return False
    
    if extensiones and not ruta.endswith(extensiones):
        logger.debug(f"'{ruta}' no tiene extensión válida. Esperado: {extensiones}")
        return False
    
    return True

# ==================== LECTURA DE ARCHIVOS ====================

def leer_lineas_archivo(ruta: str, encoding: str = 'utf-8') -> Optional[List[str]]:
    """Lee un archivo línea por línea de forma segura."""
    try:
        with open(ruta, 'r', encoding=encoding, errors='ignore') as f:
            return f.readlines()
    except Exception as e:
        logger.debug(f"Error leyendo {ruta}: {e}")
        return None

def leer_archivo_completo(ruta: str, encoding: str = 'utf-8') -> Optional[str]:
    """Lee un archivo completo de forma segura."""
    try:
        with open(ruta, 'r', encoding=encoding, errors='ignore') as f:
            return f.read()
    except Exception as e:
        logger.debug(f"Error leyendo {ruta}: {e}")
        return None

# ==================== UTILIDADES DE ARCHIVOS ====================

IGNORAR_CARPETAS_COMUN = {'.git', 'venv', '__pycache__', 'node_modules', 'reportes', 'modulos', '.venv', '.env', 'dist', 'build'}
EXTENSIONES_CODIGOS = {'.py', '.js', '.java', '.php', '.c', '.cpp', '.ts', '.tsx', '.jsx'}
EXTENSIONES_VALIDAS = EXTENSIONES_CODIGOS | {'.txt', '.json', '.env', '.html', '.yml', '.yaml', '.toml', '.lock'}

def cargar_devsecignore(ruta: str) -> Set[str]:
    """Lee el archivo .devsecignore y devuelve un set de carpetas/archivos a ignorar."""
    ignorados = set()
    archivo_ignore = os.path.join(ruta, '.devsecignore')
    if os.path.exists(archivo_ignore) and os.path.isfile(archivo_ignore):
        try:
            with open(archivo_ignore, 'r', encoding='utf-8') as f:
                for linea in f:
                    linea = linea.strip()
                    if linea and not linea.startswith('#'):
                        ignorados.add(linea)
        except Exception as e:
            logger.debug(f"Error leyendo .devsecignore: {e}")
    return ignorados

def obtener_archivos_proyecto(
    ruta: str, 
    extensiones: Set[str] = EXTENSIONES_VALIDAS,
    ignorar_carpetas: Set[str] = None
) -> List[str]:
    """Retorna lista de archivos del proyecto filtrando carpetas y extensiones."""
    
    if ignorar_carpetas is None:
        ignorar_carpetas = IGNORAR_CARPETAS_COMUN
        
    if not validar_ruta(ruta):
        return []
    
    ignorados_totales = ignorar_carpetas | cargar_devsecignore(ruta)
    
    archivos = []
    try:
        for raiz, directorios, archivos_dir in os.walk(ruta):
            # Filtra carpetas ignoradas in-place para no entrar
            directorios[:] = [d for d in directorios if d not in ignorados_totales]
            
            for archivo in archivos_dir:
                if archivo in ignorados_totales:
                    continue
                ext = os.path.splitext(archivo)[1].lower()
                if ext in extensiones or archivo.lower() in extensiones:
                    ruta_completa = os.path.join(raiz, archivo)
                    archivos.append(ruta_completa)
    except Exception as e:
        logger.warning(f"Error recorriendo {ruta}: {e}")
    
    return archivos

def obtener_archivos_por_tipo(
    ruta: str,
    tipo: str = "python",
    ignorar_carpetas: Set[str] = None
) -> List[str]:
    """Retorna archivos específicos por tipo (python, js, docker, etc)."""
    
    if ignorar_carpetas is None:
        ignorar_carpetas = IGNORAR_CARPETAS_COMUN
        
    tipo_extensiones = {
        "python": {'.py'},
        "javascript": {'.js', '.jsx', '.ts', '.tsx'},
        "java": {'.java'},
        "php": {'.php'},
        "c": {'.c', '.cpp', '.h'},
        "docker": {"Dockerfile"},  # Caso especial
        "configs": {'.json', '.yaml', '.yml', '.toml'},
        "web": {'.html', '.css', '.scss'},
    }
    
    extensiones = tipo_extensiones.get(tipo, EXTENSIONES_VALIDAS)
    
    if tipo == "docker":
        # Búsqueda especial para Dockerfiles
        ignorados_totales = ignorar_carpetas | cargar_devsecignore(ruta)
        archivos = []
        for raiz, directorios, archivos_dir in os.walk(ruta):
            directorios[:] = [d for d in directorios if d not in ignorados_totales]
            if "Dockerfile" in archivos_dir and "Dockerfile" not in ignorados_totales:
                archivos.append(os.path.join(raiz, "Dockerfile"))
        return archivos
    
    return obtener_archivos_proyecto(ruta, extensiones, ignorar_carpetas)

# ==================== CACHÉ SIMPLE ====================

class CacheSimple:
    """Caché en memoria con expiración por tiempo."""
    
    def __init__(self, ttl_segundos: int = 3600):
        self.datos: Dict[str, Dict[str, Any]] = {}
        self.ttl = ttl_segundos
    
    def get(self, clave: str) -> Optional[Any]:
        """Obtiene valor del caché si no expiró."""
        if clave not in self.datos:
            return None
        
        entrada = self.datos[clave]
        tiempo_actual = datetime.now().timestamp()
        
        if tiempo_actual - entrada['timestamp'] > self.ttl:
            del self.datos[clave]
            return None
        
        return entrada['valor']
    
    def set(self, clave: str, valor: Any) -> None:
        """Guarda valor en caché con timestamp."""
        self.datos[clave] = {
            'valor': valor,
            'timestamp': datetime.now().timestamp()
        }
    
    def clear(self) -> None:
        """Limpia el caché."""
        self.datos.clear()
    
    def get_stats(self) -> Dict[str, int]:
        """Retorna estadísticas del caché."""
        return {
            'items': len(self.datos),
            'ttl_segundos': self.ttl
        }

# Caché global
cache_global = CacheSimple()

# ==================== FORMATOS ====================

def formatear_tamaño(bytes_val: int) -> str:
    """Convierte bytes a formato legible (KB, MB, GB)."""
    for unidad in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unidad}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} TB"

def formatear_tiempo(segundos: float) -> str:
    """Convierte segundos a formato legible (ms, s, min)."""
    if segundos < 0.001:
        return f"{segundos*1000000:.0f} µs"
    elif segundos < 1:
        return f"{segundos*1000:.1f} ms"
    elif segundos < 60:
        return f"{segundos:.1f} s"
    else:
        minutos = segundos / 60
        return f"{minutos:.1f} min"

# ==================== RESULTADOS ====================

class ResultadoAnalisis:
    """Estructura estándar para resultados de análisis."""
    
    def __init__(self, modulo: str, exito: bool, mensaje: str = "", hallazgos: List[Dict] = None):
        self.modulo = modulo
        self.exito = exito
        self.mensaje = mensaje
        self.hallazgos = hallazgos or []
        self.timestamp = datetime.now().isoformat()
    
    def agregar_hallazgo(self, tipo: str, descripcion: str, severidad: str = "info", linea: int = 0, remediacion: Optional[Dict] = None):
        """Agrega un hallazgo al resultado con opcional sugerencia de remediación."""
        hallazgo = {
            'tipo': tipo,
            'descripcion': descripcion,
            'severidad': severidad,
            'linea': linea,
            'timestamp': datetime.now().isoformat()
        }
        
        # Agrega remediación si está disponible
        if remediacion:
            hallazgo['remediacion'] = {
                'exito': remediacion.get('exito', False),
                'riesgo': remediacion.get('riesgo', ''),
                'solucion': remediacion.get('solucion', ''),
                'codigo_corregido': remediacion.get('codigo_corregido', ''),
                'proveedor': remediacion.get('proveedor', 'N/A')
            }
        
        self.hallazgos.append(hallazgo)
    
    def a_dict(self) -> Dict[str, Any]:
        """Convierte resultado a diccionario."""
        return {
            'modulo': self.modulo,
            'exito': self.exito,
            'mensaje': self.mensaje,
            'hallazgos': self.hallazgos,
            'total_hallazgos': len(self.hallazgos),
            'timestamp': self.timestamp
        }
    
    def a_json(self) -> str:
        """Convierte resultado a JSON."""
        return json.dumps(self.a_dict(), indent=2, ensure_ascii=False)


if __name__ == "__main__":
    # Test básico
    logger.info("✅ Utils cargado correctamente")
    print(f"Caché: {cache_global.get_stats()}")
