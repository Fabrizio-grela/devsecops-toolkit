import os
import pytest
import tempfile
from unittest.mock import patch, MagicMock
from utils import ResultadoAnalisis, obtener_archivos_proyecto, EXTENSIONES_VALIDAS

from modulos import sast, leaks, aws_scanner
from botocore.exceptions import ClientError

TEST_DIR = os.path.join(os.path.dirname(__file__), "test_samples")

def test_sast_deteccion():
    """Prueba que el módulo SAST detecte el eval() y el SQL Injection en test_samples."""
    resultado = sast.analizar(TEST_DIR)
    
    assert isinstance(resultado, ResultadoAnalisis), "SAST debe retornar un objeto ResultadoAnalisis"
    assert resultado.exito is True
    
    assert len(resultado.hallazgos) >= 2, "Debería encontrar al menos 2 vulnerabilidades"
    
    tipos_encontrados = [h['tipo'] for h in resultado.hallazgos]
    assert 'JS' in tipos_encontrados, "Debería detectar la vulnerabilidad en vulnerable.js"
    assert 'JAVA' in tipos_encontrados, "Debería detectar la vulnerabilidad en Vulnerable.java"

def test_leaks_deteccion():
    """Prueba que el módulo Leaks detecte los tokens en prueba_seguridad.txt."""
    resultado = leaks.analizar(TEST_DIR)
    
    assert isinstance(resultado, ResultadoAnalisis), "Leaks debe retornar un objeto ResultadoAnalisis"
    assert resultado.exito is True
    
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

def test_ignorar_carpetas_comun():
    """Prueba que el mecanismo de exclusión ignore correctamente carpetas y archivos en la lista negra."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Crear un archivo válido
        os.makedirs(os.path.join(tmp_dir, "src"))
        valid_file = os.path.join(tmp_dir, "src", "main.py")
        with open(valid_file, "w") as f:
            f.write("print('hola')")
            
        # Crear una carpeta ignorada y un archivo dentro
        os.makedirs(os.path.join(tmp_dir, "node_modules"))
        ignored_file1 = os.path.join(tmp_dir, "node_modules", "index.js")
        with open(ignored_file1, "w") as f:
            f.write("console.log('hola')")
            
        # Crear un archivo explícitamente ignorado en la raíz
        ignored_file2 = os.path.join(tmp_dir, ".ai_cache.json")
        with open(ignored_file2, "w") as f:
            f.write("{}")
            
        archivos = obtener_archivos_proyecto(tmp_dir, EXTENSIONES_VALIDAS)
        
        assert valid_file in archivos, "El archivo válido debería ser encontrado"
        assert ignored_file1 not in archivos, "Los archivos en node_modules deben ser ignorados"
        assert ignored_file2 not in archivos, "El archivo .ai_cache.json debe ser ignorado"

@patch('modulos.aws_scanner.boto3.client')
def test_aws_scanner_mock(mock_boto3_client):
    """Prueba el módulo AWS simulando la infraestructura de la nube."""
    
    # 1. Simular autenticación exitosa (STS)
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
    
    # 2. Simular un S3 Bucket inseguro
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'bucket-super-inseguro'}]}
    # Simulamos que AWS nos dice "Este bucket no tiene bloqueo"
    mock_s3.get_public_access_block.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchPublicAccessBlockConfiguration'}}, 'GetPublicAccessBlock'
    )
    
    # 3. Simular un usuario de IAM sin MFA
    mock_iam = MagicMock()
    mock_iam.list_users.return_value = {'Users': [{'UserName': 'dev_user'}]}
    mock_iam.list_mfa_devices.return_value = {'MFADevices': []}
    
    # Enrutar el simulador
    mock_boto3_client.side_effect = lambda service: {'sts': mock_sts, 's3': mock_s3, 'iam': mock_iam}.get(service, MagicMock())
    
    resultado = aws_scanner.analizar(".")
    
    assert resultado.exito is True, "El análisis debe marcarse como exitoso"
    assert len(resultado.hallazgos) == 2, "Debe detectar el Bucket vulnerable y el Usuario sin MFA"
    
    tipos_encontrados = [h['tipo'] for h in resultado.hallazgos]
    assert "S3 Acceso Público" in tipos_encontrados
    assert "IAM sin MFA" in tipos_encontrados