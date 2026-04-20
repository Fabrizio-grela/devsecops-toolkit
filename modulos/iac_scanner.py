import os
import re

IGNORAR_CARPETAS = ['.git', 'venv', '__pycache__', 'node_modules', 'reportes', 'modulos']

# Reglas específicas para detectar malas prácticas en Docker
REGLAS_IAC = {
    "Imagen base sin versionar (Usa 'latest')": r"(?i)^FROM\s+[a-zA-Z0-9_\-\/]+(:latest)?\s*$",
    "Puerto SSH (22) expuesto": r"(?i)^EXPOSE\s+.*?\b22\b",
    "Secretos en variables de entorno": r"(?i)^(ENV|ARG)\s+.*(PASSWORD|SECRET|TOKEN|API_KEY)\s*="
}

def analizar(ruta_proyecto):
    hallazgos = []
    
    for raiz, directorios, archivos in os.walk(ruta_proyecto):
        directorios[:] = [d for d in directorios if d not in IGNORAR_CARPETAS]
        
        for archivo in archivos:
            # Apunta específicamente a archivos de infraestructura
            if archivo == "Dockerfile" or archivo.endswith(('.yml', '.yaml', '.tf')):
                ruta_completa = os.path.join(raiz, archivo)
                try:
                    with open(ruta_completa, 'r', encoding='utf-8') as f:
                        contenido = f.readlines()
                        
                        tiene_usuario_no_root = False
                        
                        for num_linea, linea in enumerate(contenido, 1):
                            linea = linea.strip()
                            
                            # Si detecta que cambia a un usuario seguro, lo anota
                            if linea.upper().startswith("USER ") and "root" not in linea.lower():
                                tiene_usuario_no_root = True

                            # Pasa las reglas Regex
                            for nombre_regla, patron in REGLAS_IAC.items():
                                if re.search(patron, linea):
                                    hallazgos.append(f"[{nombre_regla}] en {archivo} (Línea {num_linea})")
                        
                        # Análisis de contexto: Si es un Dockerfile y nunca cambió de usuario, corre como root
                        if archivo == "Dockerfile" and not tiene_usuario_no_root:
                            hallazgos.append(f"[Contenedor corre con privilegios ROOT] en {archivo} (Fallo Global)")
                            
                except Exception:
                    pass 
    
    if not hallazgos:
        return "Infraestructura segura. No se detectaron malas prácticas de IaC."
    
    resultado_final = f"Se detectaron {len(hallazgos)} fallos de configuración en infraestructura:\n"
    for h in hallazgos:
        resultado_final += f"        - 🏗️ {h}\n"
        
    return resultado_final