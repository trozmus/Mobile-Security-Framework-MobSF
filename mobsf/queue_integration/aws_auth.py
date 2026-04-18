# -*- coding: utf_8 -*-
"""
AWS IAM authentication utilities for Redis/MemoryDB and RDS/PostgreSQL.

Provides token generation for IAM-based authentication to AWS services.
"""

import logging
import os

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import BotoCoreError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


def get_memorydb_auth_token() -> str:
    """Get MemoryDB password from AWS Secrets Manager.

    MemoryDB doesn't have built-in IAM token generation like RDS.
    Instead, fetch the password from Secrets Manager.

    Returns:
        MemoryDB password from Secrets Manager

    Raises:
        ImportError: if boto3 is not installed
        ValueError: if MEMORYDB_SECRET_NAME is not set
        BotoCoreError: if AWS credentials are not available or secret not found
    """
    if not BOTO3_AVAILABLE:
        raise ImportError(
            'boto3 is required for MemoryDB authentication. Install with: pip install boto3'
        )

    region = os.getenv('AWS_REGION', 'us-east-1')
    secret_name = os.getenv('MEMORYDB_SECRET_NAME')

    # Alternative: fetch secret by cluster name pattern
    if not secret_name:
        cluster_name = os.getenv('MEMORYDB_CLUSTER_NAME')
        if cluster_name:
            # Try common naming pattern: {cluster_name}-password or rds!{cluster_name}
            secret_name = f"{cluster_name}-password"
            logger.debug(f'No MEMORYDB_SECRET_NAME set, using pattern: {secret_name}')

    if not secret_name:
        raise ValueError(
            'MEMORYDB_SECRET_NAME or MEMORYDB_CLUSTER_NAME environment variable is required'
        )

    try:
        client = boto3.client('secretsmanager', region_name=region)
        logger.debug(f'Fetching MemoryDB secret: {secret_name}')

        response = client.get_secret_value(SecretId=secret_name)

        # Handle both string and JSON secrets
        if 'SecretString' in response:
            import json
            try:
                secret_dict = json.loads(response['SecretString'])
                # Try common password field names
                password = secret_dict.get('password') or secret_dict.get(
                    'MEMORYDB_PASSWORD') or secret_dict.get('auth_token')
                if password:
                    logger.info(
                        f'Retrieved MemoryDB password from Secrets Manager: {secret_name}')
                    return password
            except json.JSONDecodeError:
                # If not JSON, treat as plain string password
                password = response['SecretString']
                logger.info(
                    f'Retrieved MemoryDB password (plaintext) from Secrets Manager: {secret_name}')
                return password
        elif 'SecretBinary' in response:
            password = response['SecretBinary'].decode('utf-8')
            logger.info(
                f'Retrieved MemoryDB password (binary) from Secrets Manager: {secret_name}')
            return password

        raise ValueError(f'No password found in secret: {secret_name}')

    except Exception as e:
        logger.error(
            f'Failed to get MemoryDB password from Secrets Manager: {type(e).__name__}: {e}')
        raise


def get_rds_auth_token() -> str:
    """Generate IAM auth token for AWS RDS/Aurora PostgreSQL (valid for 15 min).

    Returns:
        Signed authentication token to use as database password

    Raises:
        ImportError: if boto3 is not installed
        ValueError: if required environment variables are not set
        BotoCoreError, NoCredentialsError: if AWS credentials are not available
    """
    if not BOTO3_AVAILABLE:
        raise ImportError(
            'boto3 is required for IAM authentication. Install with: pip install boto3'
        )

    region = os.getenv('AWS_REGION', 'us-east-1')
    host = os.getenv('POSTGRES_HOST')
    port = int(os.getenv('POSTGRES_PORT', '5432'))
    username = os.getenv('POSTGRES_USER')

    if not host or not username:
        raise ValueError(
            'POSTGRES_HOST and POSTGRES_USER environment variables are required'
        )

    try:
        client = boto3.client('rds', region_name=region)
        token = client.generate_db_auth_token(
            DBHostname=host,
            Port=port,
            DBUsername=username,
            Region=region,
        )
        logger.debug(
            'Generated RDS IAM auth token for user=%s host=%s',
            username, host
        )
        return token
    except (BotoCoreError, NoCredentialsError) as e:
        logger.error('Failed to generate RDS IAM auth token: %s', e)
        raise


def should_use_iam_auth() -> bool:
    """Check if IAM authentication should be used based on NODE_ENV.

    Returns:
        True if NODE_ENV is 'dev' or 'prod', False otherwise (local development)
    """
    node_env = os.getenv('NODE_ENV', 'local').lower()
    return node_env in ('dev', 'prod')


def get_memorydb_connection():
    """Create a production-grade MemoryDB connection with SSL, timeout, and retry logic.

    Handles:
    - Password fetch from AWS Secrets Manager
    - SSL/TLS encryption
    - Connection timeouts (5s connect, 10s read)
    - Keep-alive and health checks
    - Retry on timeout

    Returns:
        redis.Redis connection object

    Raises:
        ImportError: if redis or boto3 not installed
        ValueError: if required environment variables not set
        BotoCoreError: if AWS credentials unavailable
    """
    try:
        import redis
    except ImportError:
        raise ImportError('redis is required. Install with: pip install redis')

    logger.info('[MEMORYDB_CONN] Initializing production MemoryDB connection...')

    # Get configuration
    host = os.getenv('VALKEY_HOST')
    port = int(os.getenv('VALKEY_PORT', '6379'))
    username = os.getenv('VALKEY_USERNAME', 'default')
    password = os.getenv('VALKEY_PASSWORD', '')

    if not host:
        raise ValueError('VALKEY_HOST environment variable is required')

    # Fetch password from Secrets Manager if in production and no env password
    if should_use_iam_auth() and not password:
        try:
            logger.debug('[MEMORYDB_CONN] Fetching password from Secrets Manager...')
            password = get_memorydb_auth_token()
            logger.debug('[MEMORYDB_CONN] Password retrieved from Secrets Manager')
        except Exception as e:
            logger.error(
                f'[MEMORYDB_CONN] Failed to fetch password: {type(e).__name__}: {e}')
            raise

    if not password:
        logger.warning(
            '[MEMORYDB_CONN] No password found - MemoryDB connection will fail')

    # Create SSL/TLS context
    import ssl
    ssl_context = ssl.create_default_context()

    logger.info(
        f'[MEMORYDB_CONN] Creating connection: host={host}:{port}, username={username}, ssl=True')

    try:
        connection = redis.Redis(
            host=host,
            port=port,
            username=username,
            password=password,
            ssl=True,
            ssl_certfile=None,  # Use system CA certs
            ssl_keyfile=None,
            ssl_cert_reqs='required',
            ssl_check_hostname=True,
            ssl_ca_certs=None,  # Use default CA bundle
            socket_timeout=10,  # Read timeout
            socket_connect_timeout=5,  # Connect timeout
            socket_keepalive=True,
            socket_keepalive_options={
                1: 1,  # TCP_KEEPIDLE
                2: 1,  # TCP_KEEPINTVL
                3: 5,  # TCP_KEEPCNT
            } if hasattr(redis, 'TCP_KEEPIDLE') else {},
            health_check_interval=30,  # Health check every 30s
            retry_on_timeout=True,
            max_connections=50,
        )

        logger.info('[MEMORYDB_CONN] Connection object created successfully')
        return connection

    except Exception as e:
        logger.error(
            f'[MEMORYDB_CONN] Failed to create connection: {type(e).__name__}: {e}')
        raise
