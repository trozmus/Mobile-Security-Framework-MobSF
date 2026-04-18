# -*- coding: utf_8 -*-
"""
Queue Integration API — django-ninja router.

Swagger UI:  /api/queue/docs
OpenAPI JSON: /api/queue/openapi.json
"""

import asyncio
import logging
import os
import time

from ninja import NinjaAPI, Schema
from ninja.responses import codes_4xx, codes_5xx

from bullmq import Queue

from mobsf.queue_integration.aws_auth import (
    get_memorydb_auth_token,
    should_use_iam_auth,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

api = NinjaAPI(
    title='MobSF Queue Integration API',
    version='1.0.0',
    description=(
        'Test endpoints for publishing scan jobs to the BullMQ input queue '
        'and checking queue configuration.'
    ),
    urls_namespace='queue_api',
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ScanJobRequest(Schema):
    processID: str
    url: str

    class Config:
        json_schema_extra = {
            'example': {
                'processID': 'my-process-001',
                'url': 'https://example.com/app.apk',
            }
        }


class ScanJobQueued(Schema):
    status: str
    processID: str
    queue: str


class QueueConfig(Schema):
    input_queue: str
    output_queue: str
    valkey_host: str
    valkey_port: int


class ErrorResponse(Schema):
    error: str
    message: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redis_opts() -> dict:
    """Get Redis/Valkey connection options with IAM auth support.
    
    In production (NODE_ENV=prod), generates IAM auth token for MemoryDB.
    In local/dev, uses VALKEY_PASSWORD environment variable or defaults to empty.
    """
    host = os.getenv('VALKEY_HOST', 'localhost')
    port = int(os.getenv('VALKEY_PORT', '6379'))
    username = os.getenv('VALKEY_USERNAME', 'default')
    password = os.getenv('VALKEY_PASSWORD', '')
    
    # In production, generate IAM auth token for MemoryDB
    if should_use_iam_auth() and not password:
        try:
            logger.info('[VALKEY_AUTH] Generating IAM auth token for MemoryDB...')
            password = get_memorydb_auth_token()
            logger.info(f'[VALKEY_AUTH_OK] IAM token generated for user={username}')
        except Exception as e:
            logger.error(f'[VALKEY_AUTH_ERROR] Failed to generate IAM token: {type(e).__name__}: {e}')
            logger.warning('[VALKEY_AUTH_FALLBACK] Falling back to VALKEY_PASSWORD')
            password = os.getenv('VALKEY_PASSWORD', '')
    
    opts = {
        'host': host,
        'port': port,
        'password': password,
        'username': username,
    }
    logger.debug(
        f'[REDIS_CONFIG] host={opts["host"]}:{opts["port"]}, username={opts["username"]}, password_set={bool(opts["password"])}, auth_source={"iam" if should_use_iam_auth() else "env"}')
    return opts


def _get_input_queue() -> str:
    return os.getenv('QUEUE_INPUT', 'APP-SCANN')


def _get_output_queue() -> str:
    return os.getenv('QUEUE_OUTPUT', 'APP-SCANN-RESULT')


async def _push_to_queue(process_id: str, url: str, timeout: int = 30) -> None:
    """Push job to BullMQ queue with timeout protection.
    
    Args:
        process_id: Unique process identifier
        url: URL to download APK from
        timeout: Timeout in seconds (default 30s)
    """
    queue_name = _get_input_queue()
    logger.debug(
        f'[ASYNC_PUSH_START] processID={process_id}, queue={queue_name}, url={url}, timeout={timeout}s')

    start_time = time.time()
    redis_opts = _redis_opts()

    logger.debug(
        f'[REDIS_CONNECT] Attempting connection to {redis_opts["host"]}:{redis_opts["port"]}...')
    try:
        q = Queue(queue_name, {'connection': redis_opts})
        logger.debug(f'[REDIS_CONNECT_OK] Queue object created successfully')
    except Exception as e:
        logger.error(
            f'[REDIS_CONNECT_ERROR] Failed to create Queue object: {type(e).__name__}: {e}')
        raise

    try:
        logger.debug(f'[QUEUE_ADD_START] Adding job to queue "{queue_name}"...')
        
        # Add timeout protection for queue.add operation
        try:
            job = await asyncio.wait_for(
                q.add('app-binary-scan-requested', {'processID': process_id, 'url': url}),
                timeout=timeout
            )
            elapsed = time.time() - start_time
            logger.info(
                f'[QUEUE_ADD_OK] Job added successfully in {elapsed:.2f}s | processID={process_id} | queue={queue_name} | job_id={job.id if hasattr(job, "id") else "unknown"}')
        except asyncio.TimeoutError:
            elapsed = time.time() - start_time
            logger.error(
                f'[QUEUE_ADD_TIMEOUT] Queue add operation timed out after {timeout}s | elapsed={elapsed:.2f}s | processID={process_id} | queue={queue_name}')
            raise TimeoutError(f'Queue add operation timed out after {timeout}s')
            
    except TimeoutError:
        raise
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(
            f'[QUEUE_ADD_ERROR] Failed after {elapsed:.2f}s: {type(e).__name__}: {e} | processID={process_id}')
        raise
    finally:
        try:
            logger.debug(f'[REDIS_CLOSE_START] Closing queue connection...')
            await q.close()
            logger.debug(f'[REDIS_CLOSE_OK] Queue connection closed')
        except Exception as e:
            logger.warning(
                f'[REDIS_CLOSE_ERROR] Error closing queue: {type(e).__name__}: {e}')


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@api.post(
    '/push',
    response={200: ScanJobQueued, codes_4xx: ErrorResponse, codes_5xx: ErrorResponse},
    summary='Push a scan job to the input queue',
    description=(
        'Publishes a new scan job to the BullMQ input queue (`APP-SCANN` by default). '
        'The queue worker will download the APK from `url`, run a static analysis '
        'and publish the result to the output queue (`APP-SCANN-RESULT` by default).'
    ),
    tags=['Queue'],
)
def push_scan_job(request, payload: ScanJobRequest):
    request_id = f"{payload.processID}-{int(time.time()*1000)}"

    logger.info(
        f'[REQUEST_START] request_id={request_id} | processID={payload.processID} | url={payload.url}')
    logger.debug(
        f'[REQUEST_DETAILS] method={request.method}, path={request.path}, client_ip={request.META.get("REMOTE_ADDR")}')

    queue_name = _get_input_queue()
    start_time = time.time()

    try:
        logger.debug(
            f'[ASYNCIO_RUN_START] request_id={request_id} | Starting async task...')
        asyncio.run(_push_to_queue(payload.processID, payload.url))
        elapsed = time.time() - start_time
        logger.info(
            f'[REQUEST_SUCCESS] request_id={request_id} | Completed in {elapsed:.2f}s | processID={payload.processID}')

    except TimeoutError as exc:
        elapsed = time.time() - start_time
        logger.error(
            f'[REQUEST_TIMEOUT] request_id={request_id} | Timeout after {elapsed:.2f}s | Error: {exc}')
        return 504, ErrorResponse(error='timeout', message=f'Queue operation timed out: {str(exc)}')
    except asyncio.TimeoutError as exc:
        elapsed = time.time() - start_time
        logger.error(
            f'[REQUEST_TIMEOUT] request_id={request_id} | Asyncio timeout after {elapsed:.2f}s | Error: {exc}')
        return 504, ErrorResponse(error='timeout', message='Queue operation timed out')
    except Exception as exc:
        elapsed = time.time() - start_time
        logger.exception(
            f'[REQUEST_ERROR] request_id={request_id} | Failed after {elapsed:.2f}s to push job to queue "{queue_name}"')
        logger.error(
            f'[ERROR_DETAILS] Exception type={type(exc).__name__}, Message={str(exc)}')
        return 500, ErrorResponse(error='queue_error', message=str(exc))

    return 200, ScanJobQueued(
        status='queued',
        processID=payload.processID,
        queue=queue_name,
    )


@api.get(
    '/config',
    response={200: QueueConfig},
    summary='Get current queue configuration',
    description='Returns the active queue names and Valkey connection info (no credentials).',
    tags=['Queue'],
)
def get_queue_config(request):
    opts = _redis_opts()
    return QueueConfig(
        input_queue=_get_input_queue(),
        output_queue=_get_output_queue(),
        valkey_host=opts['host'],
        valkey_port=opts['port'],
    )
