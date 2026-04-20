import os
import re
import requests

IGNORAR_CARPETAS = ['.git', 'venv', '__pycache__', 'node_modules', 'reportes', 'modulos']

def consultar_osv(paquete, version):
    """Consulta la API pública de vulnerabilidades para un paquete específico"""
    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version,
        "package": {
            "name": paquete,
            "ecosystem": "PyPI" 
        }
    }
    
    try:
        # Hace la petición POST a la base de datos
        respuesta = requests.post(url, json=payload)
        if respuesta.status_code == 200 and "vulns" in respuesta.json():
            # Si responde con 'vulns', la librería está comprometida
            vulnerabilidades = respuesta.json()["vulns"]
            
            # Agarra el ID oficial de la vulnerabilidad (Ej: CVE-2018-18074)
            cve_id = vulnerabilidades[0].get("id", "Vulnerabilidad Desconocida")
            return cve_id
    except Exception:
        pass
    
    return None

def analizar(ruta_proyecto):
    hallazgos = []
    
    for raiz, directorios, archivos in os.walk(ruta_proyecto):
        directorios[:] = [d for d in directorios if d not in IGNORAR_CARPETAS]
        
        # Solo busca archivos de dependencias de Python
        if "requirements.txt" in archivos:
            ruta_completa = os.path.join(raiz, "requirements.txt")
            try:
                with open(ruta_completa, 'r', encoding='utf-8') as f:
                    for num_linea, linea in enumerate(f, 1):
                        linea = linea.strip()
                        
                        # Usa Regex para capturar "nombre_paquete==1.2.3"
                        match = re.match(r"^([a-zA-Z0-9_\-]+)==([0-9\.]+)", linea)
                        if match:
                            paquete = match.group(1)
                            version = match.group(2)
                            
                            # Valida contra la API de internet
                            cve = consultar_osv(paquete, version)
                            if cve:
                                hallazgos.append(f"[{paquete} v{version}] es VULNERABLE! Reporte oficial: {cve} (Línea {num_linea})")
            except Exception:
                pass 
    
    if not hallazgos:
        return "Las dependencias están actualizadas y seguras."
    
    resultado_final = f"Se detectaron {len(hallazgos)} dependencias desactualizadas o comprometidas:\n"
    for h in hallazgos:
        resultado_final += f"        - 🐛 {h}\n"
        
    return resultado_final