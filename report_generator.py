"""
Generador de reportes JSON y HTML para DevSecOps Toolkit
Convierte resultados de análisis en reportes documentados
"""

import csv
import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from utils import logger, ResultadoAnalisis

class GeneradorReportes:
    """Genera reportes en múltiples formatos."""
    
    def __init__(self, directorio_reportes: str = "reportes"):
        self.directorio = directorio_reportes
        self._crear_directorio()
    
    def _crear_directorio(self):
        """Crea la carpeta de reportes si no existe."""
        try:
            Path(self.directorio).mkdir(exist_ok=True)
            logger.debug(f"Directorio de reportes: {self.directorio}")
        except Exception as e:
            logger.error(f"No se pudo crear directorio de reportes: {e}")
    
    def generar_nombre_reporte(self, prefijo: str = "scan") -> str:
        """Genera nombre único para el reporte con timestamp."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{prefijo}_{timestamp}"
    
    def guardar_json(self, 
                     resultados: List[ResultadoAnalisis], 
                     nombre_reporte: Optional[str] = None,
                     ruta_escaneo: str = ".") -> str:
        """Guarda resultados en JSON con metadata."""
        
        if not nombre_reporte:
            nombre_reporte = self.generar_nombre_reporte()
        
        reporte = {
            "metadata": {
                "titulo": "DevSecOps Toolkit - Reporte de Seguridad",
                "version": "2.0",
                "fecha_generacion": datetime.now().isoformat(),
                "ruta_escaneo": ruta_escaneo,
                "total_modulos": len(resultados),
            },
            "resumen": {
                "total_hallazgos": sum(r.a_dict()['total_hallazgos'] for r in resultados),
                "modulos_exitosos": sum(1 for r in resultados if r.exito),
                "modulos_fallidos": sum(1 for r in resultados if not r.exito),
                "criticos": 0,
                "altos": 0,
                "medios": 0,
                "bajos": 0,
            },
            "resultados": [r.a_dict() for r in resultados]
        }
        
        # Contabiliza severidades
        for resultado in reporte['resultados']:
            for hallazgo in resultado['hallazgos']:
                severidad = hallazgo.get('severidad', 'info')
                if severidad == 'critico':
                    reporte['resumen']['criticos'] += 1
                elif severidad == 'alto':
                    reporte['resumen']['altos'] += 1
                elif severidad == 'medio':
                    reporte['resumen']['medios'] += 1
                elif severidad == 'bajo':
                    reporte['resumen']['bajos'] += 1
        
        # Guarda archivo
        ruta_archivo = os.path.join(self.directorio, f"{nombre_reporte}.json")
        try:
            with open(ruta_archivo, 'w', encoding='utf-8') as f:
                json.dump(reporte, f, indent=2, ensure_ascii=False)
            logger.info(f"✅ Reporte JSON guardado: {ruta_archivo}")
            return ruta_archivo
        except Exception as e:
            logger.error(f"Error guardando JSON: {e}")
            return ""
    
    def guardar_csv(self, resultados: List[ResultadoAnalisis], nombre_reporte: Optional[str] = None) -> str:
        """Guarda resultados en formato CSV (Excel)."""
        if not nombre_reporte:
            nombre_reporte = self.generar_nombre_reporte()
            
        ruta_archivo = os.path.join(self.directorio, f"{nombre_reporte}.csv")
        try:
            with open(ruta_archivo, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f, delimiter=';')
                writer.writerow(['Módulo', 'Severidad', 'Tipo', 'Archivo', 'Línea', 'Descripción', 'Sugerencia IA'])
                
                for r in resultados:
                    for h in r.hallazgos:
                        solucion_ia = h.get('remediacion', {}).get('solucion', '') if 'remediacion' in h else ''
                        writer.writerow([
                            r.modulo, h.get('severidad', '').upper(), h.get('tipo', ''), 
                            h.get('archivo', ''), h.get('linea', ''), h.get('descripcion', ''), solucion_ia
                        ])
            logger.info(f"✅ Reporte CSV guardado: {ruta_archivo}")
            return ruta_archivo
        except Exception as e:
            logger.error(f"Error guardando CSV: {e}")
            return ""

    def guardar_html(self, 
                     resultados: List[ResultadoAnalisis],
                     nombre_reporte: Optional[str] = None,
                     ruta_escaneo: str = ".") -> str:
        """Genera reporte HTML interactivo."""
        
        if not nombre_reporte:
            nombre_reporte = self.generar_nombre_reporte()
        
        # Calcula estadísticas
        total_hallazgos = sum(r.a_dict()['total_hallazgos'] for r in resultados)
        modulos_exitosos = sum(1 for r in resultados if r.exito)
        modulos_fallidos = sum(1 for r in resultados if not r.exito)
        
        # Construye tabla de hallazgos con mejor formato
        filas_hallazgos = ""
        color_map = {
            'critico': 'danger',
            'alto': 'warning',
            'medio': 'info',
            'bajo': 'secondary',
            'info': 'secondary'
        }
        
        for resultado in resultados:
            for hallazgo in resultado.a_dict()['hallazgos']:
                color = color_map.get(hallazgo.get('severidad', 'info'), 'secondary')
                severidad = hallazgo.get('severidad', 'info').upper()
                
                filas_hallazgos += f"""
                <tr>
                    <td><strong class="text-muted">{resultado.modulo}</strong></td>
                    <td><code>{hallazgo.get('tipo', 'N/A')}</code></td>
                    <td><span class="badge bg-{color}">{severidad}</span></td>
                    <td class="text-start">{hallazgo.get('descripcion', '')}</td>
                    <td class="text-center"><small>{hallazgo.get('linea', '-')}</small></td>
                </tr>
                """
                
        # Construye sección de resumen de mitigaciones IA
        seccion_ia = ""
        mitigaciones_ia = []
        
        for resultado in resultados:
            for hallazgo in resultado.a_dict()['hallazgos']:
                remediacion = hallazgo.get('remediacion')
                if remediacion and isinstance(remediacion, dict) and remediacion.get('exito'):
                    mitigaciones_ia.append({
                        'modulo': resultado.modulo,
                        'tipo': hallazgo.get('tipo', 'N/A'),
                        'archivo': hallazgo.get('archivo', 'N/A'),
                        'linea': hallazgo.get('linea', '-'),
                        'riesgo': remediacion.get('riesgo', ''),
                        'solucion': remediacion.get('solucion', ''),
                        'codigo_corregido': remediacion.get('codigo_corregido', ''),
                        'proveedor': remediacion.get('proveedor', 'IA')
                    })
                    
        if mitigaciones_ia:
            filas_ia = ""
            for m in mitigaciones_ia:
                filas_ia += f"""
                <div class="card mb-3 border-start border-4 border-success">
                    <div class="card-body">
                        <h6 class="text-success mb-2">[{m['modulo']}] {m['tipo']} en <code>{m['archivo']}</code> (Línea {m['linea']})</h6>
                        <p class="mb-1"><strong>⚠️ Riesgo:</strong> {m['riesgo']}</p>
                        <p class="mb-2"><strong>✅ Solución:</strong> {m['solucion']}</p>
                        {f'<div class="bg-dark p-2 rounded mt-2 text-light" style="font-family: monospace; font-size: 0.85em; white-space: pre-wrap;">{m["codigo_corregido"].replace("<", "&lt;").replace(">", "&gt;")}</div>' if m['codigo_corregido'] else ''}
                        <div class="text-end mt-2"><small class="text-muted">🤖 Generado por {m['proveedor']}</small></div>
                    </div>
                </div>
                """
            seccion_ia = f'<h3 class="mt-5">🤖 Resumen de Mitigaciones Sugeridas (IA)</h3>{filas_ia}'
        
        # Construye secciones de módulos con mejor formato
        secciones_modulos = ""
        color_map = {
            'critico': 'danger',
            'alto': 'warning',
            'medio': 'info',
            'bajo': 'secondary'
        }
        
        for resultado in resultados:
            estado_badge = "success" if resultado.exito else "danger"
            estado_icono = "✅" if resultado.exito else "❌"
            
            # Extrae el mensaje formateado
            mensaje_limpio = resultado.mensaje.replace('\n', '<br>')
            
            # Cuenta por severidad
            criticos = resultado.mensaje.count('[CRITICO]')
            altos = resultado.mensaje.count('[ALTO]')
            medios = resultado.mensaje.count('[MEDIO]')
            bajos = resultado.mensaje.count('[BAJO]')
            
            secciones_modulos += f"""
            <div class="card mb-4 border-start border-4 border-{estado_badge}">
                <div class="card-header bg-light">
                    <div class="d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">{estado_icono} <strong>{resultado.modulo}</strong></h5>
                        <span class="badge bg-{estado_badge}">{'Exitoso' if resultado.exito else 'Fallido'}</span>
                    </div>
                </div>
                <div class="card-body">
                    <div class="alert alert-light border" role="alert" style="border-left: 4px solid #0d6efd;">
                        <strong>📝 Resumen:</strong> {resultado.a_dict()['total_hallazgos']} hallazgos encontrados
                    </div>
                    
                    <h6 class="mt-3 mb-3">Detalles por Severidad:</h6>
                    <div class="row g-2 mb-3">
                        {f'<div class="col-auto"><span class="badge bg-danger">🔴 Críticos: {criticos}</span></div>' if criticos > 0 else ''}
                        {f'<div class="col-auto"><span class="badge bg-warning">🟠 Altos: {altos}</span></div>' if altos > 0 else ''}
                        {f'<div class="col-auto"><span class="badge bg-info">🔵 Medios: {medios}</span></div>' if medios > 0 else ''}
                        {f'<div class="col-auto"><span class="badge bg-secondary">⚪ Bajos: {bajos}</span></div>' if bajos > 0 else ''}
                    </div>
                    
                    <h6 class="mt-4 mb-2">📋 Hallazgos Detallados:</h6>
                    <div class="bg-dark p-3 rounded" style="color: #fff; font-family: 'Courier New', monospace; font-size: 0.9em; max-height: 400px; overflow-y: auto;">
                        <code>{mensaje_limpio}</code>
                    </div>
                </div>
            </div>
            """
        
        secciones_modulos = secciones_modulos or '<p class="text-muted">Sin resultados</p>'
        
        html = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>DevSecOps Toolkit - Reporte de Seguridad</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                :root {{
                    --primary: #667eea;
                    --secondary: #764ba2;
                    --danger: #dc3545;
                    --warning: #ffc107;
                    --info: #0dcaf0;
                }}
                
                body {{ 
                    background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    min-height: 100vh;
                    padding-bottom: 50px;
                }}
                
                .navbar {{ 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
                }}
                
                .navbar-brand {{ 
                    font-weight: 700;
                    font-size: 1.4em;
                    letter-spacing: 0.5px;
                }}
                
                .container {{
                    max-width: 1200px;
                }}
                
                .header-stats {{
                    background: white;
                    border-radius: 12px;
                    padding: 30px;
                    margin-bottom: 40px;
                    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
                    border-top: 4px solid var(--primary);
                }}
                
                .stat-card {{ 
                    text-align: center;
                    padding: 20px;
                    border-radius: 8px;
                    transition: transform 0.3s ease, box-shadow 0.3s ease;
                }}
                
                .stat-card:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                }}
                
                .stat-number {{ 
                    font-size: 2.8em;
                    font-weight: 800;
                    color: var(--primary);
                    line-height: 1;
                    margin-bottom: 10px;
                }}
                
                .stat-label {{ 
                    color: #666;
                    font-size: 0.95em;
                    font-weight: 600;
                    letter-spacing: 0.5px;
                }}
                
                .timestamp {{
                    color: #999;
                    font-size: 0.85em;
                    line-height: 1.6;
                }}
                
                .card {{
                    border: none;
                    border-radius: 10px;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
                    margin-bottom: 25px;
                    transition: box-shadow 0.3s ease;
                    overflow: hidden;
                }}
                
                .card:hover {{
                    box-shadow: 0 8px 20px rgba(0, 0, 0, 0.12);
                }}
                
                .card-header {{
                    background: linear-gradient(135deg, #f5f7fa 0%, #e9ecef 100%);
                    border-bottom: 2px solid var(--primary);
                    padding: 20px;
                }}
                
                .card-body {{
                    padding: 25px;
                    background: white;
                }}
                
                .card h5 {{
                    color: #222;
                    font-weight: 700;
                    letter-spacing: 0.3px;
                }}
                
                .badge {{
                    font-size: 0.9em;
                    padding: 6px 12px;
                    font-weight: 600;
                    letter-spacing: 0.3px;
                    border-radius: 20px;
                }}
                
                .alert {{
                    border-radius: 8px;
                    border: 2px solid #dee2e6;
                    background-color: #f8f9fa;
                    padding: 15px 20px;
                    margin-bottom: 20px;
                }}
                
                .alert strong {{
                    color: #333;
                }}
                
                code {{
                    background: transparent;
                    color: #e83e8c;
                    font-weight: 600;
                    padding: 2px 6px;
                }}
                
                table {{
                    font-size: 0.95em;
                    margin-top: 20px;
                }}
                
                .table thead {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    font-weight: 700;
                }}
                
                .table tbody tr {{
                    border-bottom: 1px solid #e9ecef;
                    transition: background-color 0.2s ease;
                }}
                
                .table tbody tr:hover {{
                    background-color: #f8f9fa;
                }}
                
                .table-responsive {{
                    border-radius: 8px;
                    overflow: hidden;
                    border: 1px solid #dee2e6;
                }}
                
                h3 {{
                    color: #222;
                    font-weight: 700;
                    margin-top: 40px;
                    margin-bottom: 25px;
                    padding-bottom: 12px;
                    border-bottom: 3px solid var(--primary);
                }}
                
                h6 {{
                    color: #444;
                    font-weight: 700;
                    letter-spacing: 0.3px;
                }}
                
                .footer {{
                    text-align: center;
                    color: #666;
                    margin-top: 50px;
                    padding-top: 30px;
                    border-top: 2px solid rgba(0, 0, 0, 0.1);
                }}
                
                .footer strong {{
                    color: #333;
                }}
                
                .border-start.border-4 {{
                    border-radius: 10px;
                }}
            </style>
        </head>
        <body>
            <nav class="navbar navbar-dark sticky-top">
                <div class="container-fluid">
                    <span class="navbar-brand">🛡️ DevSecOps Toolkit</span>
                    <span class="navbar-text text-white">Reporte de Seguridad v2.0</span>
                </div>
            </nav>
            
            <div class="container mt-5">
                <div class="header-stats">
                    <div class="row">
                        <div class="col-md-3 col-sm-6">
                            <div class="stat-card">
                                <div class="stat-number" style="color: #0dcaf0;">{total_hallazgos}</div>
                                <div class="stat-label">Hallazgos Totales</div>
                            </div>
                        </div>
                        <div class="col-md-3 col-sm-6">
                            <div class="stat-card">
                                <div class="stat-number" style="color: #28a745;">{modulos_exitosos}</div>
                                <div class="stat-label">Módulos Exitosos</div>
                            </div>
                        </div>
                        <div class="col-md-3 col-sm-6">
                            <div class="stat-card">
                                <div class="stat-number" style="color: #dc3545;">{modulos_fallidos}</div>
                                <div class="stat-label">Módulos Fallidos</div>
                            </div>
                        </div>
                        <div class="col-md-3 col-sm-6">
                            <div class="stat-card">
                                <div class="timestamp" style="margin-top: 0;">
                                    <div><strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong></div>
                                    <div style="font-size: 0.8em; margin-top: 5px;">📁 {ruta_escaneo}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <h3>📊 Resultados Detallados</h3>
                {secciones_modulos}
                
                <h3>📋 Tabla Consolidada de Hallazgos</h3>
                <div class="card">
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover mb-0">
                                <thead>
                                    <tr>
                                        <th>Módulo</th>
                                        <th>Tipo</th>
                                        <th>Severidad</th>
                                        <th class="text-start">Descripción</th>
                                        <th class="text-center">Línea</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {filas_hallazgos if filas_hallazgos else '<tr><td colspan="5" class="text-center text-muted">✅ No hay hallazgos</td></tr>'}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                {seccion_ia}
                
                <div class="footer">
                    <p>Generado por <strong>DevSecOps Toolkit v2.0</strong></p>
                    <p class="timestamp">{datetime.now().isoformat()}</p>
                </div>
            </div>
            
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
        """
        
        # Guarda archivo
        ruta_archivo = os.path.join(self.directorio, f"{nombre_reporte}.html")
        try:
            with open(ruta_archivo, 'w', encoding='utf-8') as f:
                f.write(html)
            logger.info(f"✅ Reporte HTML guardado: {ruta_archivo}")
            return ruta_archivo
        except Exception as e:
            logger.error(f"Error guardando HTML: {e}")
            return ""
    
    def _generar_tabla_hallazgos(self, resultado: ResultadoAnalisis) -> str:
        """Genera tabla HTML de hallazgos para un módulo."""
        if not resultado.hallazgos:
            return "<p class='text-muted'>Sin hallazgos</p>"
        
        filas = ""
        for hallazgo in resultado.hallazgos:
            severidad = hallazgo.get('severidad', 'info')
            color = {
                'critico': 'danger',
                'alto': 'warning',
                'medio': 'warning',
                'bajo': 'info'
            }.get(severidad, 'secondary')
            
            filas += f"""
            <tr>
                <td><span class="badge bg-{color}">{severidad.upper()}</span></td>
                <td>{hallazgo.get('tipo', 'N/A')}</td>
                <td>{hallazgo.get('descripcion', '')}</td>
            </tr>
            """
        
        return f"""
        <div class="table-responsive">
            <table class="table table-sm table-borderless">
                <tbody>
                    {filas}
                </tbody>
            </table>
        </div>
        """
    
    def guardar_todos(self, 
                      resultados: List[ResultadoAnalisis],
                      nombre_base: Optional[str] = None,
                      ruta_escaneo: str = ".") -> Dict[str, str]:
        """Guarda reportes en JSON, HTML y CSV, retorna rutas."""
        
        if not nombre_base:
            nombre_base = self.generar_nombre_reporte()
        
        return {
            'json': self.guardar_json(resultados, nombre_base, ruta_escaneo),
            'html': self.guardar_html(resultados, nombre_base, ruta_escaneo),
            'csv': self.guardar_csv(resultados, nombre_base)
        }


if __name__ == "__main__":
    # Test
    from utils import ResultadoAnalisis
    
    gen = GeneradorReportes()
    
    r1 = ResultadoAnalisis("SAST", True, "Análisis completado")
    r1.agregar_hallazgo("RCE", "Uso de eval()", "critico", 42)
    
    r2 = ResultadoAnalisis("SCA", True, "Análisis completado")
    r2.agregar_hallazgo("CVE", "requests-2.28.0 vulnerable", "alto", 0)
    
    reportes = gen.guardar_todos([r1, r2], ruta_escaneo=".")
    print(f"✅ Reportes generados: {reportes}")
