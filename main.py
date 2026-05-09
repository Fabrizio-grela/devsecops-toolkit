#!/usr/bin/env python3
import argparse
import os
import time
import sys
import importlib
import tempfile
import subprocess
import shutil
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Tuple, Any
import config_manager
from utils import logger, validar_ruta, ResultadoAnalisis
from report_generator import GeneradorReportes

def mostrar_banner():
    print("""
    ██████╗ ███████╗██╗   ██╗███████╗███████╗ ██████╗
    ██╔══██╗██╔════╝██║   ██║██╔════╝██╔════╝██╔════╝
    ██║  ██║█████╗  ██║   ██║███████╗█████╗  ██║      
    ██║  ██║██╔══╝  ╚██╗ ██╔╝╚════██║██╔══╝  ██║      
    ██████╔╝███████╗ ╚████╔╝ ███████║███████╗╚██████╗
    ╚═════╝ ╚══════╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝
           DevSecOps Toolkit v2.0 - Multi-Core
    --------------------------------------------------
    """)

def menu_interactivo():
    mostrar_banner()
    logger.info("📁 Bienvenido al modo interactivo de DevSecOps Toolkit\n")
    
    ruta = input("👉 Ingresá ruta o URL de GitHub (Enter para carpeta actual): ").strip()
    if not ruta: ruta = "."
    
    if not ruta.startswith(("http://", "https://", "git@")) and not validar_ruta(ruta):
        logger.error("Ruta inválida. Abortando.")
        sys.exit(1)
        
    print("\n🛠️  ¿Qué motor querés ejecutar?")
    print("  1. 🔑 Secrets & Leaks")
    print("  2. ☢️  Código SAST (Multi-lenguaje)")
    print("  3. 🐛 Dependencias SCA")
    print("  4. 🏗️  Infraestructura IaC")
    print("  5. 🌐 Threat Intel (VirusTotal)")
    print("  6. ☁️  Cloud Security (AWS)")
    print("  7. 🚀 ESCANEO COMPLETO")
    
    opcion = input("\n👉 Elegí una opción (1-7): ").strip()
    nombre_reporte = input("👉 Ingresá un nombre para los reportes (Enter para autogenerado): ").strip()
    args = argparse.Namespace(ruta=ruta, leaks=False, sast=False, sca=False, intel=False, iac=False, aws=False, todo=False, nombre_reporte=nombre_reporte)
    
    if opcion == '1': args.leaks = True
    elif opcion == '2': args.sast = True
    elif opcion == '3': args.sca = True
    elif opcion == '4': args.iac = True
    elif opcion == '5': args.intel = True
    elif opcion == '6': args.aws = True
    elif opcion == '7': args.todo = True
    else:
        logger.error("❌ Opción no válida.")
        sys.exit(1)
    return args

def ejecutar_modulo(nombre: str, nombre_archivo: str, ruta: str) -> ResultadoAnalisis:
    """Ejecuta un módulo y retorna ResultadoAnalisis."""
    try:
        logger.debug(f"Iniciando módulo: {nombre}")
        modulo = importlib.import_module(f"modulos.{nombre_archivo}")
        resultado = modulo.analizar(ruta)
        
        # Si el módulo ya devuelve un ResultadoAnalisis, lo usamos directo
        if isinstance(resultado, ResultadoAnalisis):
            analisis = resultado
            analisis.modulo = nombre # Aseguramos el nombre amigable (ej: "Secrets/Leaks")
        else:
            analisis = ResultadoAnalisis(nombre, True, str(resultado))
            
        logger.debug(f"✅ {nombre} completado")
        return analisis
    except Exception as e:
        logger.error(f"Error en {nombre}: {e}")
        return ResultadoAnalisis(nombre, False, f"Error: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='DevSecOps Toolkit.')
    parser.add_argument('ruta', nargs='?', help='Ruta del proyecto')
    parser.add_argument('--leaks', action='store_true')
    parser.add_argument('--sast', action='store_true')
    parser.add_argument('--sca', action='store_true')
    parser.add_argument('--intel', action='store_true')
    parser.add_argument('--iac', action='store_true')
    parser.add_argument('--aws', action='store_true')
    parser.add_argument('--todo', action='store_true')
    parser.add_argument('-n', '--nombre-reporte', type=str, default='', help='Nombre personalizado para los reportes')
    
    if len(sys.argv) == 1:
        args = menu_interactivo()
    else:
        args = parser.parse_args()
        mostrar_banner()
        if not args.ruta: args.ruta = "."
            
    # --- Cargar configuración inicial (IA y VirusTotal) ---
    # Esto invoca el asistente interactivo si no existe config.json
    config = config_manager.load_config()
    vt_key = config.get("api_keys", {}).get("virustotal", "")
    if vt_key and not os.getenv("VT_API_KEY"):
        os.environ["VT_API_KEY"] = vt_key

    ruta_original = args.ruta
    repo_temporal = None
    
    # --- Soporte nativo para GitHub / Git ---
    if args.ruta.startswith(("http://", "https://", "git@")):
        logger.info(f"📦 URL de Git detectada. Clonando repositorio: {args.ruta}")
        repo_temporal = tempfile.mkdtemp(prefix="devsec_repo_")
        try:
            # Clona solo el último commit (--depth 1) para que sea súper rápido
            subprocess.run(["git", "clone", "--depth", "1", args.ruta, repo_temporal], check=True, capture_output=True)
            args.ruta = repo_temporal
            logger.info("✅ Repositorio descargado en memoria temporal para el análisis.\n")
        except Exception as e:
            logger.error("❌ Error al clonar. Verificá que 'git' esté instalado y el repo sea público.")
            sys.exit(1)

    # Valida ruta
    if not validar_ruta(args.ruta):
        logger.error(f"La ruta '{args.ruta}' no existe o no es accesible.")
        return

    tareas = []
    if args.todo or args.leaks: tareas.append(("Secrets/Leaks", "leaks"))
    if args.todo or args.sast: tareas.append(("Código SAST", "sast"))
    if args.todo or args.sca: tareas.append(("Dependencias SCA", "sca"))
    if args.todo or args.iac: tareas.append(("Infraestructura IaC", "iac_scanner"))
    if args.todo or args.aws: tareas.append(("Cloud Security AWS", "aws_scanner"))

    if (args.todo or args.intel) and not os.getenv("VT_API_KEY"):
        logger.warning("Se requiere API Key de VirusTotal")
        
        # Evitar bloquear la ejecución si corre en GitHub Actions (CI/CD)
        if sys.stdout.isatty() and not os.environ.get("CI"):
            clave = input("👉 Pegá tu API Key (Enter para saltar): ").strip()
            if clave:
                os.environ["VT_API_KEY"] = clave
                tareas.append(("Threat Intel", "threat_intel"))
    elif args.todo or args.intel:
        tareas.append(("Threat Intel", "threat_intel"))

    if not tareas:
        logger.warning("No se seleccionó ningún módulo.")
        return

    ruta_absoluta = os.path.abspath(args.ruta)
    logger.info(f"📁 Analizando: {ruta_absoluta}")
    logger.info(f"⚡ Disparando {len(tareas)} motores en paralelo...\n")
    
    inicio = time.time()
    resultados_list: List[ResultadoAnalisis] = []
    
    try:
        with ProcessPoolExecutor() as executor:
            futuros = [executor.submit(ejecutar_modulo, n, a, args.ruta) for n, a in tareas]
            
            print("--- RESULTADOS EN TIEMPO REAL ---")
            
            completados = 0
            total_tareas = len(tareas)
            
            for f in as_completed(futuros):
                resultado = f.result()
                
                # Limpia la ruta temporal de los reportes para que queden prolijos
                if repo_temporal:
                    ruta_temp = repo_temporal + os.sep
                    resultado.mensaje = resultado.mensaje.replace(ruta_temp, "").replace(repo_temporal, "[REPO_GITHUB]")
                    for h in resultado.hallazgos:
                        if 'archivo' in h and isinstance(h['archivo'], str):
                            h['archivo'] = h['archivo'].replace(ruta_temp, "").replace(repo_temporal, "[REPO_GITHUB]")
                            
                resultados_list.append(resultado)
                completados += 1
                estado = "✅" if resultado.exito else "❌"
                mensaje_corto = resultado.mensaje.replace('\n', ' ')[:65].strip()
                print(f"[{completados}/{total_tareas}] {estado} {resultado.modulo}: {mensaje_corto}...")

        # Imprimir todos los mensajes detallados al final para no romper la barra
        print("\n" + "="*60)
        print("📄 DETALLE DE LOS HALLAZGOS")
        print("="*60)
        for res in resultados_list:
            if res.mensaje:
                print(res.mensaje)

        tiempo_total = time.time() - inicio
        logger.info(f"\n⏱️  Finalizado en {tiempo_total:.2f} segundos.")
        
        # Genera reportes
        logger.info("\n📊 Generando reportes...")
        gen = GeneradorReportes()
        nombre_base = getattr(args, 'nombre_reporte', '') or None
        reportes = gen.guardar_todos(resultados_list, nombre_base=nombre_base, ruta_escaneo=ruta_original)
        
        print(f"\n{'='*60}")
        print(f"📋 REPORTES GENERADOS:")
        print(f"  📄 JSON: {reportes['json']}")
        print(f"  🌐 HTML: {reportes['html']}")
        print(f"  📊 CSV:  {reportes['csv']}")
        print(f"{'='*60}\n")
        
        # --- Limpieza de credenciales ---
        # Solo pregunta si hay un humano interactuando en la consola
        if sys.stdout.isatty() and not os.environ.get("CI"):
            respuesta = input("❓ ¿Querés eliminar las API Keys usadas en esta sesión por seguridad? (s/N): ").strip().lower()
            if respuesta in ['s', 'si', 'y', 'yes']:
                if config_manager.delete_config():
                    logger.info("✅ Credenciales eliminadas con éxito. Se te volverán a pedir en el próximo escaneo.")
                else:
                    logger.warning("⚠️ No se pudo eliminar la configuración.")
            else:
                if config_manager.obfuscate_config():
                    logger.info("🔒 Configuración ofuscada para proteger tus API Keys de miradas indiscretas.")
        
    except KeyboardInterrupt:
        logger.warning("\n⚠️  Escaneo interrumpido por el usuario.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error no esperado: {e}")
        sys.exit(1)
    finally:
        # Limpieza de repositorio temporal
        if repo_temporal and os.path.exists(repo_temporal):
            try:
                shutil.rmtree(repo_temporal, ignore_errors=True)
                logger.info("🧹 Repositorio temporal eliminado de tu equipo.")
            except Exception:
                pass

if __name__ == '__main__':
    import multiprocessing
    multiprocessing.freeze_support()
    main()