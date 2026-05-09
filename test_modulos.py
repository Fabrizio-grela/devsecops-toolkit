import os
import pytest
from utils import ResultadoAnalisis

# Importamos los módulos a testear
from modulos import sast, leaks

# Ruta a la carpeta de ejemplos vulnerables que ya tenés armada
TEST_DIR = os.path.join(os.path.dirname(__file__), "test_samples")

def test_sast_deteccion():
    """Prueba que el módulo SAST detecte el eval() y el SQL Injection en test_samples."""
    resultado = sast.analizar(TEST_DIR)
    
    # 1. Validar que retorna el objeto correcto
    assert isinstance(resultado, ResultadoAnalisis), "SAST debe retornar un objeto ResultadoAnalisis"
    assert resultado.exito is True
    
    # 2. Validar que encontró vulnerabilidades
    assert len(resultado.hallazgos) >= 2, "Debería encontrar al menos 2 vulnerabilidades"
    
    # 3. Validar que parseó bien los tipos
    tipos_encontrados = [h['tipo'] for h in resultado.hallazgos]
    assert 'JS' in tipos_encontrados, "Debería detectar la vulnerabilidad en vulnerable.js"
    assert 'JAVA' in tipos_encontrados, "Debería detectar la vulnerabilidad en Vulnerable.java"

def test_leaks_deteccion():
    """Prueba que el módulo Leaks detecte los tokens en prueba_seguridad.txt."""
    resultado = leaks.analizar(TEST_DIR)
    
    assert isinstance(resultado, ResultadoAnalisis), "Leaks debe retornar un objeto ResultadoAnalisis"
    assert resultado.exito is True
    
    # Validar que encontró el API Key y el Token de AWS
    tipos_encontrados = [h['tipo'] for h in resultado.hallazgos]
    assert 'API Key Genérica' in tipos_encontrados, "Debería detectar la API Key genérica"
    assert 'Token de AWS' in tipos_encontrados, "Debería detectar el token de AWS"

def test_resultado_analisis_estructura():
    """Prueba que la clase ResultadoAnalisis se serialice bien para los reportes."""
    resultado = ResultadoAnalisis("TestModulo", True, "Test Exitoso")
    resultado.agregar_hallazgo("XSS", "Cross Site Scripting", "alto", 10)
    
    diccionario = resultado.a_dict()
    assert diccionario['modulo'] == "TestModulo"
    assert diccionario['total_hallazgos'] == 1
    assert diccionario['hallazgos'][0]['severidad'] == "alto"
    assert diccionario['hallazgos'][0]['tipo'] == "XSS"
    assert 'timestamp' in diccionario