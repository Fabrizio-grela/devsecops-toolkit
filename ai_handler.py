"""
AI Handler - Integración con múltiples proveedores de IA
Genera sugerencias de remediación automática para vulnerabilidades.
Soporta: Gemini, OpenAI, Anthropic, Ollama
"""

import json
import hashlib
import os
import tempfile
import time
from typing import Optional, Dict
from utils import logger

import config_manager

try:
    from google import genai
except ImportError:
    genai = None

def get_ai_cache_path() -> str:
    """Calcula la ruta del caché basándose en la ubicación de la configuración."""
    base_dir = os.path.dirname(config_manager._get_effective_path()) or "."
    return os.path.join(base_dir, ".ai_cache.json")

_ai_cache_memory = None

def load_ai_cache() -> dict:
    """Carga el caché de IA desde el disco usando la ruta dinámica."""
    global _ai_cache_memory
    if _ai_cache_memory is not None:
        return _ai_cache_memory
        
    cache_path = get_ai_cache_path()
    _ai_cache_memory = {}
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                _ai_cache_memory = json.load(f)
        except Exception:
            pass
    return _ai_cache_memory

def save_ai_cache(cache_data: dict):
    """Guarda el caché de IA en el disco en la misma carpeta que config.json."""
    try:
        with open(get_ai_cache_path(), 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def validar_codigo_ia(codigo: str, lenguaje: str) -> bool:
    """Pasa el código sugerido por la IA por el motor SAST/IaC para evitar alucinaciones vulnerables."""
    if not codigo:
        return True
        
    try:
        from modulos import sast, iac_scanner
    except ImportError:
        return True
        
    lenguaje = lenguaje.lower()
    ext_map = {
        'python': '.py', 'javascript': '.js', 'java': '.java', 
        'php': '.php', 'c': '.c', 'cpp': '.cpp',
        'dockerfile': '', 'terraform': '.tf', 'kubernetes': '.yml', 'yaml': '.yml'
    }
    ext = ext_map.get(lenguaje, '.txt')
    
    # Usar un directorio temporal para poder nombrar el archivo "Dockerfile" y que el escáner lo reconozca
    with tempfile.TemporaryDirectory() as tmpdir:
        nombre_archivo = "Dockerfile" if lenguaje == "dockerfile" else f"temp{ext}"
        tmp_path = os.path.join(tmpdir, nombre_archivo)
        
        with open(tmp_path, 'w', encoding='utf-8') as tmp:
            tmp.write(codigo)
            
        try:
            # Derivar al escáner correspondiente según el lenguaje
            if lenguaje == 'dockerfile':
                vulnerabilidades = iac_scanner.scan_dockerfile(tmp_path)
            elif lenguaje == 'terraform':
                vulnerabilidades = iac_scanner.scan_generico_iac(tmp_path, iac_scanner.REGLAS_TERRAFORM)
            elif lenguaje in ['kubernetes', 'k8s', 'yaml']:
                vulnerabilidades = iac_scanner.scan_generico_iac(tmp_path, iac_scanner.REGLAS_K8S)
            else:
                vulnerabilidades = sast.scan_sast(tmp_path)
                
            if vulnerabilidades:
                logger.debug(f"🚨 Validación IA falló: Escáner detectó '{vulnerabilidades[0]['descripcion']}' en la sugerencia.")
                return False
            return True
        except Exception as e:
            logger.debug(f"Error validando código IA: {e}")
            return True

def get_remediation(vuln_type: str, code_snippet: str, language: str = "python") -> Optional[Dict[str, str]]:
    """
    Función principal que recibe el problema y genera remediación.
    
    Args:
        vuln_type: Tipo de vulnerabilidad (ej: "Inyección SQL", "RCE")
        code_snippet: Fragmento de código vulnerable
        language: Lenguaje de programación
    
    Returns:
        Dict con estructura: {
            'exito': bool,
            'riesgo': str,
            'solucion': str,
            'codigo_corregido': str,
            'proveedor': str
        }
    """
    
    codigo_hash = hashlib.md5(code_snippet.encode('utf-8')).hexdigest()[:8]
    cache_key = f"remediate_{vuln_type}_{language}_{codigo_hash}"
    
    ai_cache = load_ai_cache()
    if cache_key in ai_cache:
        logger.debug(f"✓ Caché hit (persistente): remediación para {vuln_type}")
        return ai_cache[cache_key]
    
    settings = config_manager.get_ai_settings()
    provider = settings.get("ai_provider", "gemini")
    model = settings.get("ai_model", "gemini-2.5-flash-lite")

    prompt_base = f"""Actuá como un Ingeniero de Seguridad AppSec experto.
He detectado la siguiente vulnerabilidad en código {language}:

🚨 **Tipo de Fallo:** {vuln_type}

📝 **Fragmento de Código Vulnerable:**
```{language}
{code_snippet}
```

Por favor respondé EXACTAMENTE en este formato (sin markdown):

[RIESGO]
Una línea explicando el peligro

[SOLUCIÓN]
Una línea explicando cómo solucionarlo. Si es aplicable, mencioná la mitigación a nivel de framework más seguro para este lenguaje (ej: Django/Flask en Python, React/Express en JS, Spring en Java).

[CÓDIGO_CORREGIDO]
El código corregido aquí
```{language}
código seguro
```

No agregues saludos, explicaciones adicionales ni otro texto.
"""
    prompt = prompt_base

    max_intentos = 2
    for intento in range(max_intentos):
        try:
            if provider == "gemini":
                resultado = ask_gemini(prompt, model)
            elif provider == "openai":
                resultado = ask_openai(prompt, model)
            elif provider == "anthropic":
                resultado = ask_anthropic(prompt, model)
            elif provider == "ollama":
                resultado = ask_ollama(prompt, model)
            else:
                resultado = None
            
            if resultado and resultado['exito']:
                if validar_codigo_ia(resultado.get('codigo_corregido', ''), language):
                    ai_cache[cache_key] = resultado
                    save_ai_cache(ai_cache)
                    return resultado
                else:
                    logger.debug(f"🔄 Intento {intento + 1}: La IA alucinó código vulnerable. Solicitando corrección...")
                    prompt = prompt_base + "\n\n⚠️ IMPORTANTE: Tu respuesta anterior fue rechazada porque el [CÓDIGO_CORREGIDO] contenía configuraciones inseguras o vulnerabilidades detectadas por el escáner. Por favor, reescribe el código para que sea 100% seguro."
            else:
                return None
                
        except Exception as e:
            logger.warning(f"Error generando remediación: {e}")
            return None
            
    return None

def parse_respuesta(text: str, proveedor: str) -> Dict[str, str]:
    """Parsea la respuesta de IA en estructura estándar."""
    
    resultado = {
        'exito': False,
        'riesgo': '',
        'solucion': '',
        'codigo_corregido': '',
        'proveedor': proveedor
    }
    
    try:
        if '[RIESGO]' in text:
            riesgo_start = text.find('[RIESGO]') + len('[RIESGO]')
            riesgo_end = text.find('[SOLUCIÓN]') if '[SOLUCIÓN]' in text else len(text)
            resultado['riesgo'] = text[riesgo_start:riesgo_end].strip()
        
        if '[SOLUCIÓN]' in text:
            solucion_start = text.find('[SOLUCIÓN]') + len('[SOLUCIÓN]')
            solucion_end = text.find('[CÓDIGO_CORREGIDO]') if '[CÓDIGO_CORREGIDO]' in text else len(text)
            resultado['solucion'] = text[solucion_start:solucion_end].strip()
        
        if '[CÓDIGO_CORREGIDO]' in text:
            codigo_start = text.find('[CÓDIGO_CORREGIDO]') + len('[CÓDIGO_CORREGIDO]')
            resultado['codigo_corregido'] = text[codigo_start:].strip()
        
        if resultado['riesgo'] and resultado['solucion']:
            resultado['exito'] = True
            logger.debug(f"✅ Remediación generada correctamente por {proveedor}")
        
    except Exception as e:
        logger.warning(f"Error parseando respuesta: {e}")
    
    return resultado

# --- Funciones específicas por Proveedor ---

def ask_gemini(prompt: str, model_name: str) -> Optional[Dict[str, str]]:
    """Consulta Google Gemini."""
    if not genai:
        logger.warning("google-genai no está instalado")
        return None
    
    api_key = config_manager.get_api_key("gemini")
    if not api_key:
        logger.warning("API Key de Gemini no configurada")
        return None

    client = genai.Client(api_key=api_key)
    max_retries = 3
    
    for intento in range(max_retries):
        try:
            logger.debug(f"📡 Consultando Gemini ({model_name})... (Intento {intento + 1}/{max_retries})")
            response = client.models.generate_content(model=model_name, contents=prompt)
            
            if response and response.text:
                return parse_respuesta(response.text, "Gemini")
            break  # Sale del bucle si responde bien pero sin texto
            
        except Exception as e:
            error_str = str(e)
            if "429" in error_str or "RESOURCE_EXHAUSTED" in error_str:
                espera = 15 * (intento + 1) # Espera 15s, luego 30s, etc.
                # Escribe en la misma línea sin hacer "Enter" y luego lo borra
                print(f"\r⏳ [Gemini API] Límite alcanzado. Pausa silenciosa de {espera}s...", end="", flush=True)
                time.sleep(espera)
                print("\r" + " " * 70 + "\r", end="", flush=True) # Limpia la línea al terminar
            else:
                logger.warning(f"Error al conectar con Gemini: {e}")
                break
    
    return None

def ask_openai(prompt: str, model_name: str) -> Optional[Dict[str, str]]:
    """Consulta OpenAI ChatGPT."""
    try:
        import openai
        
        api_key = config_manager.get_api_key("openai")
        if not api_key:
            logger.warning("API Key de OpenAI no configurada")
            return None
        
        logger.debug(f"📡 Consultando OpenAI ({model_name})...")
        
        client = openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=1000
        )
        
        if response and response.choices:
            text = response.choices[0].message.content
            return parse_respuesta(text, "OpenAI")
        
    except ImportError:
        logger.warning("openai no está instalado. Instala: pip install openai")
    except Exception as e:
        logger.warning(f"Error al conectar con OpenAI: {e}")
    
    return None

def ask_anthropic(prompt: str, model_name: str) -> Optional[Dict[str, str]]:
    """Consulta Anthropic Claude."""
    try:
        import anthropic
        
        api_key = config_manager.get_api_key("anthropic")
        if not api_key:
            logger.warning("API Key de Anthropic no configurada")
            return None
        
        logger.debug(f"📡 Consultando Anthropic ({model_name})...")
        
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=model_name,
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        if response and response.content:
            text = response.content[0].text
            return parse_respuesta(text, "Anthropic")
        
    except ImportError:
        logger.warning("anthropic no está instalado. Instala: pip install anthropic")
    except Exception as e:
        logger.warning(f"Error al conectar con Anthropic: {e}")
    
    return None

def ask_ollama(prompt: str, model_name: str) -> Optional[Dict[str, str]]:
    """Consulta Ollama (modelo local)."""
    try:
        import requests
        
        settings = config_manager.get_ai_settings()
        endpoint = settings.get("ollama_endpoint", "http://localhost:11434")
        logger.debug(f"📡 Consultando Ollama local ({model_name})...")
        
        response = requests.post(
            f"{endpoint}/api/generate",
            json={"model": model_name, "prompt": prompt, "stream": False},
            timeout=30
        )
        
        if response.status_code == 200:
            text = response.json().get("response", "")
            return parse_respuesta(text, "Ollama")
        else:
            logger.warning(f"Ollama retornó: {response.status_code}")
        
    except Exception as e:
        logger.warning(f"Error al conectar con Ollama: {e}")
    
    return None

if __name__ == "__main__":
    vuln_test = "Inyección SQL (CWE-89)"
    codigo_test = 'query = "SELECT * FROM users WHERE username = \'" + user_input + "\'"'
    
    print("\n[*] Analizando vulnerabilidad...\n")
    
    resultado = get_remediation(vuln_test, codigo_test, "python")
    
    if resultado and resultado['exito']:
        print(f"""
⚠️ RIESGO
{resultado['riesgo']}

✅ SOLUCIÓN
{resultado['solucion']}

💻 CÓDIGO CORREGIDO
{resultado['codigo_corregido']}

🤖 Proveedor: {resultado['proveedor']}
        """)
    else:
        print("[!] No se pudo generar remediación")