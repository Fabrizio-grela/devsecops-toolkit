import config_manager

# Librería nueva de Google
try:
    from google import genai
except ImportError:
    genai = None

def get_remediation(vuln_type, code_snippet):
    """
    Función principal que recibe el problema y decide a qué IA enviarlo.
    """
    settings = config_manager.get_ai_settings()
    provider = settings.get("ai_provider", "gemini")
    model = settings.get("ai_model", "gemini-2.5-flash-lite") # Modelo nuevo

    # El PROMPT MAESTRO (Sin saludos, formato limpio)
    prompt = f"""Actuá como un Ingeniero de Seguridad AppSec.
He detectado la siguiente vulnerabilidad:
- Tipo de fallo: {vuln_type}

Fragmento de código vulnerable: {code_snippet}

Respondé SIGUIENDO ESTE FORMATO:

### ⚠️ Riesgo
(Explicación en una oración)

### ✅ Solución
(Código corregido)

NO agregues saludos ni otro texto.
"""

    # --- Lógica de selección de proveedor (ADENTRO de la función) ---
    if provider == "gemini":
        return ask_gemini(prompt, model)
    elif provider == "openai":
        return ask_openai(prompt, model)
    elif provider == "anthropic":
        return ask_anthropic(prompt, model)
    elif provider == "ollama":
        return ask_ollama(prompt, model)
    else:
        return "[!] Error: Proveedor de IA no válido en config.json"

# --- Funciones específicas por Proveedor ---

def ask_gemini(prompt, model_name):
    if not genai:
        return "[!] Error: Falta instalar google-genai"
    
    api_key = config_manager.get_api_key("gemini")
    if not api_key:
        return "[!] Error: No hay API Key de Gemini."

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(model=model_name, contents=prompt)
        return response.text
    except Exception as e:
        return f"[!] Error al conectar con Gemini: {e}"

def ask_openai(prompt, model_name): return "[⚙️] En construcción"
def ask_anthropic(prompt, model_name): return "[⚙️] En construcción"
def ask_ollama(prompt, model_name): return "[⚙️] En construcción"

# --- Bloque de Prueba (AL FINAL) ---
if __name__ == "__main__":
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel

    console = Console()
    console.print("\n[bold cyan][*] Analizando vulnerabilidad...[/bold cyan]\n")
    
    fallo_falso = "Inyección SQL (CWE-89)"
    codigo_falso = "query = 'SELECT * FROM users WHERE username = ' + user_input"
    
    respuesta = get_remediation(fallo_falso, codigo_falso)
    
    # code_theme="monokai" saca el amarillo y pone fondo oscuro pro
    md = Markdown(respuesta, code_theme="monokai")
    
    console.print(Panel(md, title="🛡️ [bold cyan]REMEDIACIÓN GENERADA[/bold cyan]", border_style="cyan", padding=(1, 2)))