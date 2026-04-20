import os
import re

# diccionario de vulnerabilidades
REGLAS_SAST = {
    "Uso de eval() (Peligro de RCE)": r"\beval\s*\(",
    "Ejecución de OS (Posible Inyección)": r"(os\.system|os\.popen|subprocess\.Popen|exec)\s*\(",
    "Uso de MD5 (Criptografía Débil)": r"(?i)(hashlib\.md5|md5)\s*\(",
    "Desactivación de SSL/TLS (Man-in-the-Middle)": r"(?i)verify\s*=\s*False",
    "SQLi Prone (Concatenación en SQL)": r"(?i)SELECT.*FROM.*\+"
}

IGNORAR_CARPETAS = ['.git', 'venv', '__pycache__', 'node_modules', 'reportes','modulos']
# El SAST solo analiza archivos que contengan lógica de programación
EXTENSIONES_VALIDAS = ('.py', '.js', '.php', '.java', '.ts')

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
                            # Evita analizar líneas que son comentarios
                            if linea.strip().startswith(('#', '//', '*')):
                                continue
                                
                            for nombre_regla, patron in REGLAS_SAST.items():
                                if re.search(patron, linea):
                                    hallazgos.append(f"[{nombre_regla}] en {archivo} (Línea {num_linea})")
                except Exception:
                    pass 
    
    if not hallazgos:
        return "El código parece seguro. No se encontraron funciones peligrosas básicas."
    
    resultado_final = f"Se detectaron {len(hallazgos)} malas prácticas de programación:\n"
    for h in hallazgos:
        resultado_final += f"        - ☢️ {h}\n"
        
    return resultado_final