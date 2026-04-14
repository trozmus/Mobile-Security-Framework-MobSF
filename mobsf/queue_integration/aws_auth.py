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
    """Generate IAM auth token for AWS MemoryDB (valid for 15 min).

    Returns:
        Signed authentication token to use as Redis password

    Raises:
        ImportError: if boto3 is not installed
        ValueError: if MEMORYDB_CLUSTER_NAME is not set
        BotoCoreError, NoCredentialsError: if AWS credentials are not available
    """
    if not BOTO3_AVAILABLE:
        raise ImportError(
            'boto3 is required for IAM authentication. Install with: pip install boto3'
        )

    region = os.getenv('AWS_REGION', 'us-east-1')
    username = os.getenv('VALKEY_USERNAME', 'default')
    cluster_name = os.getenv('MEMORYDB_CLUSTER_NAME')

    if not cluster_name:
        raise ValueError(
            'MEMORYDB_CLUSTER_NAME environment variable is required for IAM auth'
        )

    try:
        client = boto3.client('memorydb', region_name=region)
        token = client.generate_iam_auth_token(
            UserName=username,
            ClusterName=cluster_name,
            DurationSeconds=900,  # 15 minutes (max)
        )
        logger.debug(
            'Generated MemoryDB IAM auth token for user=%s cluster=%s',
            username, cluster_name
        )
        return token
    except (BotoCoreError, NoCredentialsError) as e:
        logger.error('Failed to generate MemoryDB IAM auth token: %s', e)
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
