"""
Módulo AWS Scanner (Cloud Security Posture Management)
Audita la cuenta de AWS en busca de configuraciones inseguras (S3 públicos, IAM sin MFA).
Requiere credenciales configuradas (aws configure o variables de entorno).
"""

from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import logger, ResultadoAnalisis

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    boto3 = None

def check_bucket_pab(s3_client, bucket_name: str) -> Optional[Dict]:
    """Verifica el PAB de un bucket individual."""
    try:
        pab = s3_client.get_public_access_block(Bucket=bucket_name)
        config = pab['PublicAccessBlockConfiguration']
        if not config.get('BlockPublicAcls') or not config.get('BlockPublicPolicy'):
            return {
                'tipo': 'S3 Acceso Público',
                'descripcion': f"El bucket '{bucket_name}' no bloquea el acceso público por completo.",
                'severidad': 'alto',
                'archivo': f"S3: {bucket_name}",
                'linea': 0
            }
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            return {
                'tipo': 'S3 Acceso Público',
                'descripcion': f"El bucket '{bucket_name}' carece de configuración de bloqueo de acceso público (PAB).",
                'severidad': 'critico',
                'archivo': f"S3: {bucket_name}",
                'linea': 0
            }
    return None

def check_s3_buckets() -> List[Dict]:
    """Busca buckets S3 que no tengan el bloqueo de acceso público activado."""
    hallazgos = []
    try:
        s3 = boto3.client('s3')
        response = s3.list_buckets()
        
        buckets = [b['Name'] for b in response.get('Buckets', [])]
        with ThreadPoolExecutor(max_workers=10) as executor:
            futuros = [executor.submit(check_bucket_pab, s3, b) for b in buckets]
            for futuro in as_completed(futuros):
                res = futuro.result()
                if res:
                    hallazgos.append(res)
                    
    except Exception as e:
        logger.debug(f"Error escaneando S3 (¿Faltan permisos?): {e}")
    return hallazgos

def check_user_mfa(iam_client, user_name: str) -> Optional[Dict]:
    """Verifica el MFA de un usuario individual."""
    mfa_response = iam_client.list_mfa_devices(UserName=user_name)
    if not mfa_response.get('MFADevices'):
        return {
            'tipo': 'IAM sin MFA',
            'descripcion': f"El usuario IAM '{user_name}' no tiene MFA habilitado.",
            'severidad': 'alto',
            'archivo': f"IAM: {user_name}",
            'linea': 0
        }
    return None

def check_iam_mfa() -> List[Dict]:
    """Revisa que todos los usuarios IAM tengan MFA configurado."""
    hallazgos = []
    try:
        iam = boto3.client('iam')
        response = iam.list_users()
        
        users = [u['UserName'] for u in response.get('Users', [])]
        with ThreadPoolExecutor(max_workers=10) as executor:
            futuros = [executor.submit(check_user_mfa, iam, u) for u in users]
            for futuro in as_completed(futuros):
                res = futuro.result()
                if res:
                    hallazgos.append(res)
                    
    except Exception as e:
        logger.debug(f"Error escaneando IAM (¿Faltan permisos?): {e}")
    return hallazgos

def analizar(ruta_proyecto: str) -> ResultadoAnalisis:
    """Función principal ejecutada por main.py"""
    if not boto3:
        return ResultadoAnalisis('aws_scanner', False, "⚠️ boto3 no instalado. Ejecuta: pip install boto3")
    
    logger.info("☁️  Iniciando análisis de postura en AWS...")
    
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        logger.info(f"Conectado a AWS (Cuenta: {identity.get('Account')})")
    except NoCredentialsError:
        return ResultadoAnalisis('aws_scanner', False, "⚠️ No se encontraron credenciales de AWS. Usa variables de entorno AWS_ACCESS_KEY_ID.")
    except Exception as e:
        return ResultadoAnalisis('aws_scanner', False, f"⚠️ Error al conectar con AWS: {e}")

    hallazgos = []
    hallazgos.extend(check_s3_buckets())
    hallazgos.extend(check_iam_mfa())
    
    msg = f"\n☁️ Módulo: AWS SCANNER - Cloud Security\n{'='*50}\n⚠️ Se detectaron {len(hallazgos)} problemas en tu cuenta AWS." if hallazgos else "✅ AWS Seguro: No se encontraron problemas de configuración."
    
    return ResultadoAnalisis('aws_scanner', True, msg, hallazgos)