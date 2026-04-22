import json
import os

CONFIG_FILE = "config.json"

def initial_setup():
    """Asistente interactivo que se ejecuta solo la primera vez"""
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
    ai_model = "gemini-1.5-flash"
    ai_key = ""

    if opcion_ia == "2":
        ai_provider = "openai"
        ai_model = "gpt-4o-mini"
        ai_key = input("\n[🔑] Pegá tu API Key de OpenAI: ").strip()
    elif opcion_ia == "3":
        ai_provider = "anthropic"
        ai_model = "claude-3-5-sonnet-20240620" # Modelo rápido y potente de Claude
        ai_key = input("\n[🔑] Pegá tu API Key de Anthropic (Claude): ").strip()
    elif opcion_ia == "4":
        ai_provider = "ollama"
        ai_model = "llama3" 
        print("\n[ℹ️] Configurado para Ollama local. Asegurate de tenerlo corriendo (Puerto 11434).")
    else:
        # Default a Gemini si pone 1 o le pifia a la tecla
        ai_provider = "gemini"
        ai_model = "gemini-1.5-flash"
        print("\n[ℹ️] Podés conseguir tu API Key de Gemini gratis en: https://aistudio.google.com/")
        ai_key = input("[🔑] Pegá tu API Key de Gemini: ").strip()

    # 2. Configurar VirusTotal
    print("\n🦠 Para el escaneo avanzado de Threat Intel usamos VirusTotal.")
    vt_key = input("[🔑] Pegá tu API Key de VirusTotal (o apretá Enter para saltar): ").strip()

    # 3. Armar el diccionario y guardar
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
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def get_api_key(service):
    config = load_config()
    return config.get("api_keys", {}).get(service, "")

def get_ai_settings():
    config = load_config()
    return config.get("settings", {})

# Bloque de prueba
if __name__ == "__main__":
    print("[*] Iniciando prueba del módulo de configuración...")