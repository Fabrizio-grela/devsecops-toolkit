import re
import os

# Reglas multi-lenguaje (Python, JS, Java, PHP, C/C++)
RULES = {
    '.py': [
        (r'eval\(', 'Uso de eval() - Riesgo de RCE'),
        (r'os\.system\(', 'Inyección de comandos'),
        (r'pickle\.load\(', 'Deserialización insegura')
    ],
    '.js': [
        (r'eval\(', 'Inyección de código'),
        (r'innerHTML\s*=', 'Riesgo crítico de XSS'),
        (r'document\.write\(', 'Riesgo de XSS')
    ],
    '.java': [
        (r'Runtime\.getRuntime\(\)\.exec\(', 'Ejecución de comandos - Riesgo de RCE'),
        (r'Statement\.executeQuery\(', 'Posible SQL Injection')
    ],
    '.php': [
        (r'eval\(', 'Riesgo de RCE'),
        (r'include\(\$_GET', 'LFI/RFI Detectado'),
        (r'system\(', 'Ejecución de comandos')
    ],
    '.c': [
        (r'gets\(', 'Buffer Overflow (Función prohibida)'),
        (r'strcpy\(', 'Riesgo de Buffer Overflow')
    ]
}

def scan_sast(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in RULES: return []
    vulnerabilidades = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for num, linea in enumerate(f, 1):
                for patron, mensaje in RULES[ext]:
                    if re.search(patron, linea):
                        vulnerabilidades.append(f"🔴 [{ext.upper()}] {mensaje}\n   Línea {num}: {linea.strip()}")
    except: pass
    return vulnerabilidades

# ESTA ES LA FUNCIÓN QUE LLAMA TU MAIN
def analizar(ruta):
    resultados = []
    for root, _, files in os.walk(ruta):
        for file in files:
            full_path = os.path.join(root, file)
            res = scan_sast(full_path)
            if res: resultados.extend(res)
    
    return "\n".join(resultados) if resultados else "✅ No se detectaron vulnerabilidades de código."