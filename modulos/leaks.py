import os
import re

# diccionario de amenazas
REGLAS = {
    "Token de AWS": r"AKIA[0-9A-Z]{16}",
    "Clave Privada": r"-----BEGIN .* PRIVATE KEY-----",
    "Contraseña Hardcodeada": r"(?i)(password|passwd|pwd|secret)\s*=\s*['\"][^'\"]+['\"]",
    "API Key Genérica": r"(?i)(api_key|apikey|token)\s*=\s*['\"][a-zA-Z0-9_\-]{16,}['\"]"
}

IGNORAR_CARPETAS = ['.git', 'venv', '__pycache__', 'node_modules', 'reportes','modulos']
EXTENSIONES_VALIDAS = ('.py', '.js', '.txt', '.json', '.env', '.html', '.yml', '.yaml')

def analizar(ruta_proyecto):
    hallazgos = []
    
    for raiz, directorios, archivos in os.walk(ruta_proyecto):
        directorios[:] = [d for d in directorios if d not in IGNORAR_CARPETAS]
        
        for archivo in archivos:
            if archivo.endswith(EXTENSIONES_VALIDAS):
                ruta_completa = os.path.join(raiz, archivo)
                try:
                    with open(ruta_completa, 'r', encoding='utf-8') as f:
                        for num_linea, linea in enumerate(f, 1):
                            for nombre_regla, patron in REGLAS.items():
                                if re.search(patron, linea):
                                    hallazgos.append(f"[{nombre_regla}] en {archivo} (Línea {num_linea})")
                except Exception:
                    pass 
    
    if not hallazgos:
        return "No se encontraron secretos ni credenciales expuestas."
    
    resultado_final = f"Se encontraron {len(hallazgos)} posibles secretos:\n"
    for h in hallazgos:
        resultado_final += f"        - 🚨 {h}\n"
        
    return resultado_final