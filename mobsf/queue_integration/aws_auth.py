# -*- coding: utf_8 -*-
"""
AWS IAM authentication utilities for Redis/MemoryDB and RDS/PostgreSQL.

Provides token generation for IAM-based authentication to AWS services.
"""

import logging
import os
from urllib.parse import urlencode, urlunparse, ParseResult

logger = logging.getLogger(__name__)

# Environments that should use AWS IAM authentication for MemoryDB/RDS.
IAM_AUTH_ENVS = frozenset({'dev', 'prod', 'stage'})

try:
    import boto3
    from botocore.exceptions import BotoCoreError, NoCredentialsError
    from botocore.signers import RequestSigner
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


def get_memorydb_iam_token() -> str:
    """Generate MemoryDB IAM auth token via SigV4 presigned URL (valid for 15 minutes).

    Uses AWS SigV4 RequestSigner to generate presigned URL that acts as auth token.
    This is the official AWS method for MemoryDB IAM authentication.

    Requires:
    - MemoryDB cluster with IAM auth enabled
    - Fargate task IAM role with memorydb:connect permission
    - IAM ACL user mapped to Fargate task role
    - VALKEY_HOST environment variable (cluster endpoint hostname)
    - VALKEY_USERNAME environment variable (IAM ACL username)
    - MEMORYDB_CLUSTER_NAME environment variable (cluster name, e.g., mudita-appstore-prod-memorydb)

    Returns:
        IAM auth token (presigned URL stripped of https://) - valid for 900s (15 min)

    Raises:
        ImportError: if boto3 not installed
        ValueError: if required environment variables not set
        BotoCoreError: if AWS credentials unavailable or IAM auth not configured
    """
    if not BOTO3_AVAILABLE:
        raise ImportError(
            'boto3 is required for MemoryDB IAM authentication. Install with: pip install boto3'
        )

    region = os.getenv('AWS_REGION', 'us-east-1')
    cluster_name = os.getenv('MEMORYDB_CLUSTER_NAME')
    username = os.getenv('VALKEY_USERNAME', 'default')

    if not cluster_name:
        logger.error('[MEMORYDB_IAM] MEMORYDB_CLUSTER_NAME not set')
        logger.error(
            '[MEMORYDB_IAM] Set it to cluster name, e.g.: mudita-appstore-prod-memorydb')
        raise ValueError(
            'MEMORYDB_CLUSTER_NAME environment variable is required for IAM token generation'
        )

    try:
        logger.debug(
            f'[MEMORYDB_IAM] Starting SigV4 token generation: cluster={cluster_name}, user={username}, region={region}')

        # Create MemoryDB client and get credentials for signing
        session = boto3.Session(region_name=region)
        client = session.client('memorydb')
        credentials = session.get_credentials()
        service_id = client.meta.service_model.service_id

        logger.debug(
            f'[MEMORYDB_IAM] MemoryDB client created, service_id={service_id}')

        # Create RequestSigner for SigV4 signing
        signer = RequestSigner(
            service_id=service_id,
            region_name=region,
            signing_name='memorydb',
            signature_version='v4',
            credentials=credentials,
            event_emitter=session.events
        )
        logger.debug('[MEMORYDB_IAM] RequestSigner created for SigV4 signing')

        # Build presigned URL for MemoryDB connect action
        query_params = {'Action': 'connect', 'User': username}

        url = urlunparse(ParseResult(
            scheme='https',
            netloc=cluster_name,
            path='/',
            query=urlencode(query_params),
            params='',
            fragment=''
        ))
        logger.debug(f'[MEMORYDB_IAM] Built URL: {url}')

        # Generate presigned URL (expires in 900s = 15 minutes)
        request_dict = {
            'method': 'GET',
            'url': url,
            'body': {},
            'headers': {},
            'context': {}
        }

        signed_url = signer.generate_presigned_url(
            request_dict,
            operation_name='connect',
            expires_in=900,
            region_name=region
        )
        logger.debug(
            f'[MEMORYDB_IAM] Presigned URL generated, length={len(signed_url)} chars')

        # Extract token from presigned URL (remove https:// prefix)
        token = signed_url.replace('https://', '')

        if not token:
            logger.error('[MEMORYDB_IAM] Empty token after URL stripping')
            raise ValueError('Empty token after presigned URL stripping')

        logger.info(
            f'[MEMORYDB_IAM] IAM token generated successfully for user={username}, cluster={cluster_name}')
        logger.debug(
            f'[MEMORYDB_IAM] Token length={len(token)} chars, valid for 900s (15 minutes)')
        return token

    except BotoCoreError as e:
        logger.error(f'[MEMORYDB_IAM] BotoCoreError: {type(e).__name__}: {e}')
        logger.error(
            '[MEMORYDB_IAM] Check: AWS credentials available? IAM role has rds:GenerateDbAuthToken permission? Endpoint correct?')
        raise
    except Exception as e:
        logger.error(
            f'[MEMORYDB_IAM] Failed to generate token: {type(e).__name__}: {e}')
        logger.error('[MEMORYDB_IAM] Traceback:', exc_info=True)
        raise


def get_memorydb_password_from_secrets() -> str:
    """Get MemoryDB password from environment or Secrets Manager (fallback method).

    Priority:
    1. VALKEY_PASSWORD environment variable
    2. AWS Secrets Manager secret

    Returns:
        Static password for MemoryDB

    Raises:
        ValueError: if no password found
    """
    # Try environment variable first
    password = os.getenv('VALKEY_PASSWORD', '')
    if password:
        logger.debug('[MEMORYDB_SECRET] Using password from VALKEY_PASSWORD env var')
        return password

    if not BOTO3_AVAILABLE:
        logger.error('[MEMORYDB_SECRET] boto3 not available and no VALKEY_PASSWORD set')
        raise ImportError('boto3 required for Secrets Manager access')

    region = os.getenv('AWS_REGION', 'us-east-1')
    secret_name = os.getenv('MEMORYDB_SECRET_NAME')

    # Try secret name pattern
    if not secret_name:
        cluster_name = os.getenv('MEMORYDB_CLUSTER_NAME')
        if cluster_name:
            secret_name = f"{cluster_name}-password"
            logger.debug(f'[MEMORYDB_SECRET] Using derived secret name: {secret_name}')

    if not secret_name:
        logger.error(
            '[MEMORYDB_SECRET] No MEMORYDB_SECRET_NAME or MEMORYDB_CLUSTER_NAME set')
        raise ValueError(
            'VALKEY_PASSWORD, MEMORYDB_SECRET_NAME, or MEMORYDB_CLUSTER_NAME required'
        )

    try:
        logger.debug(
            f'[MEMORYDB_SECRET] Fetching secret from Secrets Manager: {secret_name}')
        client = boto3.client('secretsmanager', region_name=region)
        response = client.get_secret_value(SecretId=secret_name)
        logger.debug('[MEMORYDB_SECRET] Secret retrieved')

        # Handle both string and JSON secrets
        if 'SecretString' in response:
            import json
            try:
                secret_dict = json.loads(response['SecretString'])
                logger.debug(f'[MEMORYDB_SECRET] Secret is JSON format')
                # Try common password field names
                password = secret_dict.get('password') or secret_dict.get(
                    'MEMORYDB_PASSWORD') or secret_dict.get('auth_token')
                if password:
                    logger.info(
                        f'[MEMORYDB_SECRET] Retrieved password from Secrets Manager (JSON): {secret_name}')
                    return password
                else:
                    logger.error('[MEMORYDB_SECRET] JSON secret missing password field')
                    raise ValueError(f'No password field in secret: {secret_name}')
            except json.JSONDecodeError:
                logger.debug('[MEMORYDB_SECRET] Secret is plaintext (not JSON)')
                password = response['SecretString']
                logger.info(
                    f'[MEMORYDB_SECRET] Retrieved password from Secrets Manager (plaintext): {secret_name}')
                return password
        elif 'SecretBinary' in response:
            logger.debug('[MEMORYDB_SECRET] Secret is binary format')
            password = response['SecretBinary'].decode('utf-8')
            logger.info(
                f'[MEMORYDB_SECRET] Retrieved password from Secrets Manager (binary): {secret_name}')
            return password

        logger.error(f'[MEMORYDB_SECRET] Secret has no SecretString or SecretBinary')
        raise ValueError(f'Invalid secret format: {secret_name}')

    except Exception as e:
        logger.error(
            f'[MEMORYDB_SECRET] Failed to get password: {type(e).__name__}: {e}')
        raise


def get_memorydb_auth_token() -> str:
    """Get MemoryDB authentication credential.

    For production-like environments (NODE_ENV=dev/prod/stage):
    - Generates short-lived IAM token via RDS API (per AWS docs for MemoryDB)
    - Token valid for 15 minutes, auto-refreshed on each connection
    - Falls back to Secrets Manager if IAM fails

    For local development:
    - Uses static password from VALKEY_PASSWORD env var
    - Or fetches from Secrets Manager if configured

    Returns:
        Authentication token/password for MemoryDB

    Raises:
        ImportError: if boto3 not installed
        ValueError: if required credentials not available
        BotoCoreError: if AWS credentials unavailable
    """
    use_iam = should_use_iam_auth()
    logger.debug(
        f'[MEMORYDB_AUTH] Auth mode: {"IAM_TOKEN" if use_iam else "LOCAL_PASSWORD"}')

    # Production: Use IAM token
    if use_iam:
        logger.debug('[MEMORYDB_AUTH] Using IAM token generation (production)')
        try:
            return get_memorydb_iam_token()
        except Exception as e:
            logger.warning(
                f'[MEMORYDB_AUTH] IAM token generation failed: {type(e).__name__}: {e}')
            logger.warning('[MEMORYDB_AUTH] Attempting fallback to Secrets Manager...')
            # Fallback to Secrets Manager
            try:
                return get_memorydb_password_from_secrets()
            except Exception as e2:
                logger.error(
                    f'[MEMORYDB_AUTH] Fallback also failed: {type(e2).__name__}: {e2}')
                raise

    # Local/dev: Use static password
    else:
        logger.debug('[MEMORYDB_AUTH] Using static password (local development)')
        return get_memorydb_password_from_secrets()


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
        True if NODE_ENV is 'dev', 'prod', or 'stage', False otherwise (local development)
    """
    node_env = os.getenv('NODE_ENV', 'local').lower()
    return node_env in IAM_AUTH_ENVS


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

    # Fetch authentication credential (IAM token or password)
    if should_use_iam_auth():
        try:
            logger.debug(
                '[MEMORYDB_CONN] Production mode: attempting IAM token generation...')
            password = get_memorydb_auth_token()
            logger.debug(
                '[MEMORYDB_CONN] Authentication credential retrieved (IAM token)')
        except Exception as e:
            logger.error(
                f'[MEMORYDB_CONN] Failed to get credential: {type(e).__name__}: {e}')
            raise
    else:
        try:
            logger.debug(
                '[MEMORYDB_CONN] Local mode: attempting to get static password...')
            password = get_memorydb_auth_token()
            logger.debug(
                '[MEMORYDB_CONN] Authentication credential retrieved (static password)')
        except Exception as e:
            logger.error(
                f'[MEMORYDB_CONN] Failed to get credential: {type(e).__name__}: {e}')
            raise

    if not password:
        logger.error(
            '[MEMORYDB_CONN] No authentication credential found - connection will fail')

    # Configure SSL based on environment
    use_ssl = should_use_iam_auth()
    if use_ssl:
        logger.debug('[MEMORYDB_CONN] SSL enabled (production)')
    else:
        logger.debug('[MEMORYDB_CONN] SSL disabled (local development)')

    logger.info(
        f'[MEMORYDB_CONN] Creating connection: host={host}:{port}, username={username}, ssl={use_ssl}')

    try:
        # Build connection kwargs
        conn_kwargs = {
            'host': host,
            'port': port,
            'username': username,
            'password': password,
            'socket_timeout': 10,  # Read timeout
            'socket_connect_timeout': 5,  # Connect timeout
            'socket_keepalive': True,
            'retry_on_timeout': True,
            'max_connections': 50,
        }

        # Add SSL settings for production
        if use_ssl:
            conn_kwargs.update({
                'ssl': True,
                'ssl_certfile': None,  # Use system CA certs
                'ssl_keyfile': None,
                'ssl_cert_reqs': 'required',
                'ssl_check_hostname': True,
                'ssl_ca_certs': None,  # Use default CA bundle
                'health_check_interval': 30,  # Health check every 30s
            })
        else:
            conn_kwargs['ssl'] = False
            logger.debug('[MEMORYDB_CONN] Local mode: SSL disabled')

        logger.debug(f'[MEMORYDB_CONN] Connection kwargs: {list(conn_kwargs.keys())}')

        logger.debug('[MEMORYDB_CONN] Creating Redis connection object...')
        connection = redis.Redis(**conn_kwargs)

        logger.info('[MEMORYDB_CONN] Connection object created successfully')
        return connection

    except Exception as e:
        logger.error(
            f'[MEMORYDB_CONN] Failed to create connection: {type(e).__name__}: {e}')
        raise
