#!/usr/bin/env python3
import argparse
import os
import time
import sys
import importlib
from concurrent.futures import ProcessPoolExecutor

def mostrar_banner():
    print("""
    ██████╗ ███████╗██╗   ██╗███████╗███████╗ ██████╗
    ██╔══██╗██╔════╝██║   ██║██╔════╝██╔════╝██╔════╝
    ██║  ██║█████╗  ██║   ██║███████╗█████╗  ██║      
    ██║  ██║██╔══╝  ╚██╗ ██╔╝╚════██║██╔══╝  ██║      
    ██████╔╝███████╗ ╚████╔╝ ███████║███████╗╚██████╗
    ╚═════╝ ╚══════╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝
           DevSecOps Toolkit v1.0 - Multi-Core
    --------------------------------------------------
    """)

def menu_interactivo():
    mostrar_banner()
    print("📁 Bienvenido al modo interactivo de DevSecOps Toolkit\n")
    
    ruta = input("👉 Ingresá la ruta a escanear (Enter para carpeta actual): ").strip()
    if not ruta: ruta = "."
        
    print("\n🛠️  ¿Qué motor querés ejecutar?")
    print("  1. 🔑 Secrets & Leaks")
    print("  2. ☢️  Código SAST (Multi-lenguaje)")
    print("  3. 🐛 Dependencias SCA")
    print("  4. 🏗️  Infraestructura IaC")
    print("  5. 🌐 Threat Intel (VirusTotal)")
    print("  6. 🚀 ESCANEO COMPLETO")
    
    opcion = input("\n👉 Elegí una opción (1-6): ").strip()
    args = argparse.Namespace(ruta=ruta, leaks=False, sast=False, sca=False, intel=False, iac=False, todo=False)
    
    if opcion == '1': args.leaks = True
    elif opcion == '2': args.sast = True
    elif opcion == '3': args.sca = True
    elif opcion == '4': args.iac = True
    elif opcion == '5': args.intel = True
    elif opcion == '6': args.todo = True
    else:
        print("❌ Opción no válida."); sys.exit(1)
    return args

def ejecutar_modulo(nombre, nombre_archivo, ruta):
    try:
        modulo = importlib.import_module(f"modulos.{nombre_archivo}")
        resultado = modulo.analizar(ruta)
        return nombre, True, resultado
    except Exception as e:
        return nombre, False, str(e)

def main():
    parser = argparse.ArgumentParser(description='DevSecOps Toolkit.')
    parser.add_argument('ruta', nargs='?', help='Ruta del proyecto')
    parser.add_argument('--leaks', action='store_true')
    parser.add_argument('--sast', action='store_true')
    parser.add_argument('--sca', action='store_true')
    parser.add_argument('--intel', action='store_true')
    parser.add_argument('--iac', action='store_true')
    parser.add_argument('--todo', action='store_true')
    
    if len(sys.argv) == 1:
        args = menu_interactivo()
    else:
        args = parser.parse_args()
        mostrar_banner()
        if not args.ruta: args.ruta = "."

    if not os.path.exists(args.ruta):
        print(f"❌ Error: La ruta '{args.ruta}' no existe."); return

    tareas = []
    if args.todo or args.leaks: tareas.append(("Secrets/Leaks", "leaks"))
    if args.todo or args.sast: tareas.append(("Código SAST", "sast"))
    if args.todo or args.sca: tareas.append(("Dependencias SCA", "sca"))
    if args.todo or args.iac: tareas.append(("Infraestructura IaC", "iac_scanner"))

    if (args.todo or args.intel) and not os.getenv("VT_API_KEY"):
        print("\n" + "="*60 + "\n🔑 Se requiere API Key de VirusTotal\n" + "="*60)
        clave = input("👉 Pegá tu API Key (Enter para saltar): ").strip()
        if clave:
            os.environ["VT_API_KEY"] = clave
            tareas.append(("Threat Intel", "threat_intel"))
    elif args.todo or args.intel:
        tareas.append(("Threat Intel", "threat_intel"))

    if not tareas: return

    print(f"📁 Analizando: {os.path.abspath(args.ruta)}\n")
    print(f"⚡ Disparando {len(tareas)} motores en paralelo...\n")
    
    inicio = time.time()
    with ProcessPoolExecutor() as executor:
        futuros = [executor.submit(ejecutar_modulo, n, a, args.ruta) for n, a in tareas]
        
        print("--- RESULTADOS ---")
        for f in futuros:
            nombre, exito, msj = f.result()
            estado = "✅ OK" if exito else "⏳ PENDIENTE/ERROR"
            print(f"\n[{estado}] {nombre}")
            if msj: print(f"    {msj}")

    print(f"\n⏱️  Finalizado en {time.time() - inicio:.2f} segundos.")

if __name__ == '__main__':
    import multiprocessing
    multiprocessing.freeze_support()
    main()