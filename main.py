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
    
    # 1. Preguntamos la ruta pero se la hacemos fácil
    ruta = input("👉 Ingresá la ruta a escanear (Apretá Enter para usar la carpeta actual): ").strip()
    if not ruta:
        ruta = "."
        
    # 2. Mostramos el menú de motores
    print("\n🛠️  ¿Qué motor querés ejecutar?")
    print("  1. 🔑 Secrets & Leaks (Buscar contraseñas perdidas)")
    print("  2. ☢️  Código SAST (Buscar malas prácticas)")
    print("  3. 🐛 Dependencias SCA (Buscar librerías vulnerables)")
    print("  4. 🏗️  Infraestructura IaC (Escanear Dockerfiles)")
    print("  5. 🌐 Threat Intel (Revisar IPs en VirusTotal)")
    print("  6. 🚀 ESCANEO COMPLETO (Todos los motores a la vez)")
    
    opcion = input("\n👉 Elegí una opción (1-6): ").strip()
    
    # Armamos un objeto falso de argumentos para engañar al resto del código
    args = argparse.Namespace(ruta=ruta, leaks=False, sast=False, sca=False, intel=False, iac=False, todo=False)
    
    if opcion == '1': args.leaks = True
    elif opcion == '2': args.sast = True
    elif opcion == '3': args.sca = True
    elif opcion == '4': args.iac = True
    elif opcion == '5': args.intel = True
    elif opcion == '6': args.todo = True
    else:
        print("❌ Opción no válida. Saliendo...")
        sys.exit(1)
        
    return args

def ejecutar_modulo(nombre, nombre_archivo, ruta):
    try:
        print(f"[*] Iniciando {nombre}...")
        modulo = importlib.import_module(f"modulos.{nombre_archivo}")
        resultado = modulo.analizar(ruta)
        return nombre, True, resultado
    except AttributeError:
        return nombre, False, "Módulo en construcción (Falta la función analizar)"
    except Exception as e:
        return nombre, False, str(e)

def main():
    parser = argparse.ArgumentParser(description='Herramienta integral de análisis estático y seguridad.')
    # Le ponemos nargs='?' para que la ruta ya no sea obligatoria al escribir el comando
    parser.add_argument('ruta', nargs='?', help='Ruta de la carpeta del proyecto a analizar')
    parser.add_argument('--leaks', action='store_true', help='Ejecutar buscador de credenciales y secretos')
    parser.add_argument('--sast', action='store_true', help='Ejecutar análisis de código inseguro')
    parser.add_argument('--sca', action='store_true', help='Ejecutar revisión de dependencias')
    parser.add_argument('--intel', action='store_true', help='Ejecutar análisis de IPs/Dominios maliciosos')
    parser.add_argument('--iac', action='store_true', help='Ejecutar escáner de Docker/Infraestructura')
    parser.add_argument('--todo', action='store_true', help='Ejecutar TODOS los motores en paralelo')
    
    # LA MAGIA: Si el usuario apretó Enter sin escribir NINGÚN argumento, lanzamos el menú
    if len(sys.argv) == 1:
        args = menu_interactivo()
    else:
        args = parser.parse_args()
        mostrar_banner()
        if not args.ruta:
            args.ruta = "."

    if not os.path.exists(args.ruta):
        print(f"❌ Error: La ruta '{args.ruta}' no existe.")
        return

    tareas = []
    if args.todo or args.leaks: tareas.append(("Secrets/Leaks", "leaks"))
    if args.todo or args.sast: tareas.append(("Código SAST", "sast"))
    if args.todo or args.sca: tareas.append(("Dependencias SCA", "sca"))
    if args.todo or args.iac: tareas.append(("Infraestructura IaC", "iac_scanner"))

    if args.todo or args.intel:
        if not os.getenv("VT_API_KEY"):
            print("\n" + "="*60)
            print("🛡️  INTERVENCIÓN REQUERIDA: THREAT INTEL")
            print("El motor necesita conectarse a VirusTotal para analizar IPs.")
            print("🔗 Podés conseguir tu clave gratuita registrándote acá:")
            print("   https://www.virustotal.com/gui/join-us")
            print("💡 NOTA: Por seguridad, tu clave NO se guardará en disco.")
            print("         Solo vivirá en la memoria RAM durante este escaneo.")
            print("-" * 60)
            clave = input("👉 Pegá tu API Key de VirusTotal (o dale Enter para saltar): ").strip()
            print("="*60 + "\n")

            if clave:
                os.environ["VT_API_KEY"] = clave
                tareas.append(("Threat Intel", "threat_intel"))
            else:
                print("⏭️  Módulo de Threat Intel desactivado para esta sesión.\n")
        else:
            tareas.append(("Threat Intel", "threat_intel"))

    if not tareas:
        print("⚠️ No seleccionaste ningún módulo o saltaste el único que elegiste.")
        return

    print(f"📁 Analizando objetivo: {os.path.abspath(args.ruta)}\n")
    inicio_tiempo = time.time()
    
    print(f"⚡ Disparando {len(tareas)} motores de análisis...")
    
    with ProcessPoolExecutor() as executor:
        futuros = [executor.submit(ejecutar_modulo, nombre, archivo, args.ruta) for nombre, archivo in tareas]
        
        print("\n--- RESULTADOS ---")
        for f in futuros:
            nombre, exito, msj = f.result()
            estado = "✅ OK" if exito else "⏳ PENDIENTE"
            print(f"[{estado}] {nombre}")
            
            if not exito:
                print(f"    -> {msj}")
            elif isinstance(msj, str) and msj:
                print(f"    -> {msj.replace(chr(10), chr(10)+'    ')}") 

    tiempo_total = time.time() - inicio_tiempo
    print(f"\n⏱️  Escaneo finalizado en {tiempo_total:.2f} segundos.")

if __name__ == '__main__':
    import multiprocessing
    multiprocessing.freeze_support()
    main()