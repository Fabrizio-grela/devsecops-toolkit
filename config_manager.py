import json
import os
import base64
import sys

CONFIG_FILE = "config.json"

def initial_setup():
    """Asistente interactivo que se ejecuta solo la primera vez"""
    # Evita bloquear en CI/CD o entornos Docker no interactivos
    if not sys.stdout.isatty() or os.environ.get("CI"):
        return {
            "api_keys": {},
            "settings": {"ai_provider": "gemini", "ai_model": "gemini-2.5-flash"},
            "paths": {}
        }
        
    print("\n" + "="*50)
    print("🚀 BIENVENIDO AL DEVSECOPS TOOLKIT v2.0 🚀")
    print("="*50)
    print("[*] Parece que es tu primera vez. Vamos a configurarlo rápido.\n")

    # 1. Configurar la Inteligencia Artificial
    print("🤖 ¿Qué Inteligencia Artificial querés usar para la remediación de código?")
    print("   1. Gemini (Recomendado, tiene capa gratuita generosa)")
    print("   2. OpenAI (ChatGPT)")
    print("   3. Anthropic (Claude)")
    print("   4. Ollama (IA Local / Sin API Key)")
    
    opcion_ia = input("\n[?] Elegí una opción (1/2/3/4) [Default: 1]: ").strip()

    ai_provider = "gemini"
    ai_model = "gemini-2.5-flash"
    ai_key = ""

    if opcion_ia == "2":
        ai_provider = "openai"
        ai_model = "gpt-4o-mini"
        ai_key = input("\n[🔑] Pegá tu API Key de OpenAI: ").strip()
    elif opcion_ia == "3":
        ai_provider = "anthropic"
        ai_model = "claude-3-5-sonnet-20240620"
        ai_key = input("\n[🔑] Pegá tu API Key de Anthropic (Claude): ").strip()
    elif opcion_ia == "4":
        ai_provider = "ollama"
        ai_model = "llama3" 
        print("\n[ℹ️] Configurado para Ollama local. Asegurate de tenerlo corriendo (Puerto 11434).")
    else:
        # Default a Gemini si pone 1 o le pifia a la tecla
        ai_provider = "gemini"
        ai_model = "gemini-2.5-flash"
        print("\n[ℹ️] Podés conseguir tu API Key de Gemini gratis en: https://aistudio.google.com/")
        ai_key = input("[🔑] Pegá tu API Key de Gemini: ").strip()

    # 2. Configurar VirusTotal
    print("\n🦠 Para el escaneo avanzado de Threat Intel usamos VirusTotal.")
    vt_key = input("[🔑] Pegá tu API Key de VirusTotal (o apretá Enter para saltar): ").strip()

    config = {
        "api_keys": {
            "virustotal": vt_key,
            "openai": ai_key if ai_provider == "openai" else "",
            "gemini": ai_key if ai_provider == "gemini" else "",
            "anthropic": ai_key if ai_provider == "anthropic" else ""
        },
        "settings": {
            "ai_provider": ai_provider,
            "ai_model": ai_model,
            "ollama_endpoint": "http://localhost:11434"
        },
        "paths": {
            "rules_dir": "rules/",
            "reports_dir": "reports/"
        }
    }

    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

    print("\n[✅] ¡Todo listo! Configuración guardada en 'config.json'.")
    print("="*50 + "\n")
    
    return config

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return initial_setup()
    
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        content = f.read().strip()
        
    try:
        if content.startswith("{"):
            return json.loads(content)
        else:
            # Intenta decodificar de Base64 si está ofuscado
            decoded = base64.b64decode(content).decode('utf-8')
            return json.loads(decoded)
    except Exception:
        # Si el archivo está corrupto, pide configurarlo de nuevo
        return initial_setup()

def get_api_key(service):
    config = load_config()
    return config.get("api_keys", {}).get(service, "")

def get_ai_settings():
    config = load_config()
    return config.get("settings", {})

def delete_config():
    """Elimina el archivo de configuración para borrar las credenciales."""
    try:
        if os.path.exists(CONFIG_FILE):
            os.remove(CONFIG_FILE)
        return True
    except Exception:
        return False

def obfuscate_config():
    """Ofusca el archivo de configuración para evitar lectura en texto plano."""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip()
            # Si no está ofuscado (comienza con llave de JSON), lo ofusca
            if content.startswith("{"):
                encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
                with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                    f.write(encoded)
        return True
    except Exception:
        return False