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
from typing import List
import config_manager
from utils import logger, validar_ruta, ResultadoAnalisis
from report_generator import GeneradorReportes

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def mostrar_banner():
    print(f"""{Colors.CYAN}{Colors.BOLD}
    ██████╗ ███████╗██╗   ██╗███████╗███████╗ ██████╗
    ██╔══██╗██╔════╝██║   ██║██╔════╝██╔════╝██╔════╝
    ██║  ██║█████╗  ██║   ██║███████╗█████╗  ██║      
    ██║  ██║██╔══╝  ╚██╗ ██╔╝╚════██║██╔══╝  ██║      
    ██████╔╝███████╗ ╚████╔╝ ███████║███████╗╚██████╗
    ╚═════╝ ╚══════╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝
           DevSecOps Toolkit v2.0 - Multi-Core
    --------------------------------------------------{Colors.RESET}
    """)

def menu_interactivo(ruta_predefinida=None):
    mostrar_banner()
    logger.info(f"{Colors.GREEN}📁 Bienvenido al modo interactivo de DevSecOps Toolkit\n{Colors.RESET}")

    if ruta_predefinida:
        ruta = ruta_predefinida
        print(f"📁 Ruta detectada: {Colors.CYAN}{ruta}{Colors.RESET}")
    else:
        # Detectar si estamos en Docker y ajustar el comportamiento
        is_in_docker = os.path.exists('/.dockerenv')
        if is_in_docker:
            prompt_text = f"👉 Ingresá ruta o URL de GitHub ({Colors.YELLOW}Tip: Usá /data para analizar la carpeta actual{Colors.RESET}): "
            default_ruta = "/data"
        else:
            prompt_text = "👉 Ingresá ruta o URL de GitHub (Enter para carpeta actual): "
            default_ruta = "."

        ruta = input(prompt_text).strip()
        if not ruta:
            ruta = default_ruta

    if not ruta.startswith(("http://", "https://", "git@")) and not validar_ruta(ruta):
        logger.error("Ruta inválida. Abortando.")
        sys.exit(1)
        
    print(f"\n{Colors.CYAN}🛠️  ¿Qué motor querés ejecutar?{Colors.RESET}")
    print(f"  {Colors.GREEN}1. 🔑 Secrets & Leaks{Colors.RESET}")
    print(f"  {Colors.GREEN}2. ☢️  Código SAST (Multi-lenguaje){Colors.RESET}")
    print(f"  {Colors.GREEN}3. 🐛 Dependencias SCA{Colors.RESET}")
    print(f"  {Colors.GREEN}4. 🏗️  Infraestructura IaC{Colors.RESET}")
    print(f"  {Colors.GREEN}5. 🌐 Threat Intel (VirusTotal){Colors.RESET}")
    print(f"  {Colors.GREEN}6. ☁️  Cloud Security (AWS){Colors.RESET}")
    print(f"  {Colors.BOLD}{Colors.YELLOW}7. 🚀 ESCANEO COMPLETO{Colors.RESET}")
    
    opcion = input(f"\n{Colors.CYAN}👉 Elegí una opción (1-7): {Colors.RESET}").strip()
    nombre_reporte = input(f"{Colors.CYAN}👉 Ingresá un nombre para los reportes (Enter para autogenerado): {Colors.RESET}").strip()
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

def procesar_ruta_reporte(entrada_usuario: str) -> tuple:
    """Procesa la entrada del usuario y mapea alias a carpetas del host en Docker."""
    if not entrada_usuario:
        return "/data/reportes", "✅ Reporte guardado en la carpeta del proyecto (reportes/)"
        
    entrada = entrada_usuario.strip().lower()
    
    alias_map = {
        'desktop': ('Desktop', 'tu Escritorio'),
        'escritorio': ('Desktop', 'tu Escritorio'),
        'downloads': ('Downloads', 'tus Descargas'),
        'descargas': ('Downloads', 'tus Descargas'),
        'documents': ('Documents', 'tus Documentos'),
        'documentos': ('Documents', 'tus Documentos')
    }
    
    if entrada in alias_map:
        nombre_carpeta, nombre_amigable = alias_map[entrada]
        # Rutas a verificar dentro del contenedor en /host
        rutas_a_probar = [f"/host/{nombre_carpeta}", f"/host/{entrada.capitalize()}"]
        for ruta in rutas_a_probar:
            if os.path.exists(ruta):
                return ruta, f"✅ Reporte guardado en {nombre_amigable}"
                
    if entrada and os.path.exists(entrada):
        return entrada, f"✅ Reporte guardado en {entrada}"
        
    return "/data/reportes", "✅ Reporte guardado en la carpeta del proyecto (reportes/)"

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
    
    args = parser.parse_args()
    
    hay_flags = any([args.leaks, args.sast, args.sca, args.intel, args.iac, args.aws, args.todo])
    
    if not hay_flags:
        args = menu_interactivo(ruta_predefinida=args.ruta)
    else:
        mostrar_banner()
        if not args.ruta: args.ruta = "."
            
    # --- Cargar configuración inicial (IA y VirusTotal) ---
    config_path = "config.json"
    if os.path.exists('/.dockerenv'):
        config_path = "/app/config.json"
        logger.debug("Usando ruta de configuración para Docker: /app/config.json")

    # Establece la ruta de configuración de forma global para que todos los módulos la usen
    config_manager.set_config_path(config_path)

    # load_config se encarga de:
    # 1. Cargar desde config_path si existe.
    # 2. Si no, lanzar el asistente interactivo para crear el archivo.
    # Las variables de entorno tienen prioridad sobre este archivo.
    config = config_manager.load_config()

    # Poblar variables de entorno desde el archivo de config si no están ya seteadas.
    # Esto mantiene la prioridad de las variables de entorno sobre el archivo.
    if config:
        # API Keys
        api_keys = config.get("api_keys", {})
        if api_keys:
            for key_name, env_var in [("virustotal", "VT_API_KEY"), ("gemini", "GEMINI_API_KEY"), ("openai", "OPENAI_API_KEY"), ("anthropic", "ANTHROPIC_API_KEY")]:
                key_value = api_keys.get(key_name)
                if key_value and not os.getenv(env_var):
                    os.environ[env_var] = key_value

    ruta_original = args.ruta
    repo_temporal = None
    
    # --- Soporte nativo para GitHub / Git ---
    if args.ruta.startswith(("http://", "https://", "git@")):
        logger.info(f"📦 URL de Git detectada. Clonando repositorio: {args.ruta}")
        repo_temporal = tempfile.mkdtemp(prefix="devsec_repo_")
        try:
            # Clona solo el último commit (--depth 1) para que sea súper rápido
            subprocess.run(["git", "clone", "--depth", "1", args.ruta, repo_temporal], check=True, capture_output=True) # nosec
            args.ruta = repo_temporal
            logger.info("✅ Repositorio descargado en memoria temporal para el análisis.\n")
        except Exception as e:
            logger.error("❌ Error al clonar. Verificá que 'git' esté instalado y el repo sea público.")
            sys.exit(1)

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
        if sys.stdout.isatty() and not os.environ.get("CI"):
            print(f"\n{Colors.YELLOW}ℹ️  El módulo de Threat Intel requiere una API Key de VirusTotal.{Colors.RESET}")
            clave = input(f"{Colors.CYAN}👉 Pegá tu API Key (o apretá Enter para omitir este módulo): {Colors.RESET}").strip()
            if clave:
                os.environ["VT_API_KEY"] = clave
                tareas.append(("Threat Intel", "threat_intel"))
            else:
                logger.info("Módulo de Threat Intel omitido por falta de API Key.")
        else:
            logger.warning("Módulo de Threat Intel omitido: No se encontró VT_API_KEY en variables de entorno.")
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
        
        # --- Opciones de guardado ---
        directorio_reportes = "reportes"
        mensaje_salida = "✅ Reporte guardado en la carpeta local"
        
        if sys.stdout.isatty() and not os.environ.get("CI"):
            print("\n" + "-"*60)
            if os.path.exists('/.dockerenv'):
                resp_dir = input("📁 ¿Dónde querés guardar el reporte? (Ej: Desktop, Downloads o Enter para defecto): ").strip()
                directorio_reportes, mensaje_salida = procesar_ruta_reporte(resp_dir)
            else:
                resp_dir = input("📁 ¿Dónde querés guardar el reporte HTML? (Enter para 'reportes/'): ").strip()
                if resp_dir:
                    directorio_reportes = resp_dir
        elif os.path.exists('/.dockerenv'):
            directorio_reportes, mensaje_salida = procesar_ruta_reporte("")

        logger.info("\n📊 Generando reporte HTML...")
        gen = GeneradorReportes(directorio_reportes=directorio_reportes)
        nombre_base = getattr(args, 'nombre_reporte', '') or None
        ruta_html = gen.guardar_html(resultados_list, nombre_reporte=nombre_base, ruta_escaneo=ruta_original)
        
        print(f"\n{'='*60}")
        print(f"📋 REPORTE GENERADO:")
        if os.path.exists('/.dockerenv'):
            print(f"  {mensaje_salida}")
            print(f"  🌐 Archivo: {os.path.basename(ruta_html)}")
        else:
            print(f"  🌐 HTML: {ruta_html}")
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