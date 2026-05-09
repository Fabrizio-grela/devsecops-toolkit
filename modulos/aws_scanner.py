"""
Módulo AWS Scanner (Cloud Security Posture Management)
Audita la cuenta de AWS en busca de configuraciones inseguras (S3 públicos, IAM sin MFA).
Requiere credenciales configuradas (aws configure o variables de entorno).
"""

import os
from typing import List, Dict, Any
from utils import logger, ResultadoAnalisis

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    boto3 = None

def check_s3_buckets() -> List[Dict]:
    """Busca buckets S3 que no tengan el bloqueo de acceso público activado."""
    hallazgos = []
    try:
        s3 = boto3.client('s3')
        response = s3.list_buckets()
        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']
            try:
                # Revisa si tiene bloqueado el acceso público
                pab = s3.get_public_access_block(Bucket=bucket_name)
                config = pab['PublicAccessBlockConfiguration']
                if not config.get('BlockPublicAcls') or not config.get('BlockPublicPolicy'):
                    hallazgos.append({
                        'tipo': 'S3 Acceso Público',
                        'descripcion': f"El bucket '{bucket_name}' no bloquea el acceso público por completo.",
                        'severidad': 'alto',
                        'archivo': f"S3: {bucket_name}",
                        'linea': 0
                    })
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    hallazgos.append({
                        'tipo': 'S3 Acceso Público',
                        'descripcion': f"El bucket '{bucket_name}' carece de configuración de bloqueo de acceso público (PAB).",
                        'severidad': 'critico',
                        'archivo': f"S3: {bucket_name}",
                        'linea': 0
                    })
    except Exception as e:
        logger.debug(f"Error escaneando S3 (¿Faltan permisos?): {e}")
    return hallazgos

def check_iam_mfa() -> List[Dict]:
    """Revisa que todos los usuarios IAM tengan MFA configurado."""
    hallazgos = []
    try:
        iam = boto3.client('iam')
        response = iam.list_users()
        for user in response.get('Users', []):
            user_name = user['UserName']
            mfa_response = iam.list_mfa_devices(UserName=user_name)
            if not mfa_response.get('MFADevices'):
                hallazgos.append({
                    'tipo': 'IAM sin MFA',
                    'descripcion': f"El usuario IAM '{user_name}' no tiene MFA habilitado.",
                    'severidad': 'alto',
                    'archivo': f"IAM: {user_name}",
                    'linea': 0
                })
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