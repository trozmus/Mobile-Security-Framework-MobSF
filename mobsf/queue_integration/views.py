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

import redis
from ninja import NinjaAPI, Schema
from ninja.responses import codes_4xx, codes_5xx

from bullmq import Queue

from mobsf.queue_integration.aws_auth import (
    get_memorydb_auth_token,
    should_use_iam_auth,
)


def _patch_bullmq_for_cluster() -> None:
    """Patch bullmq's RedisConnection to accept redis.RedisCluster.

    bullmq's RedisConnection only checks isinstance(opts, redis.Redis).
    RedisCluster is not a Redis subclass, so we add explicit support.
    We also add aclose() to RedisCluster since bullmq calls it during cleanup.
    """
    from bullmq.redis_connection import RedisConnection
    from redis.backoff import ExponentialBackoff
    from redis.retry import Retry
    from redis.exceptions import BusyLoadingError

    if getattr(RedisConnection, '_cluster_patched', False):
        return

    _original_init = RedisConnection.__init__

    def _patched_init(self, redisOpts={}):
        if isinstance(redisOpts, redis.RedisCluster):
            self.version = None
            self.conn = redisOpts
        else:
            _original_init(self, redisOpts)

    RedisConnection.__init__ = _patched_init
    RedisConnection._cluster_patched = True

    # RedisCluster has close() but bullmq calls aclose() (async)
    if not hasattr(redis.RedisCluster, 'aclose'):
        async def _aclose(self):
            self.close()
        redis.RedisCluster.aclose = _aclose


_patch_bullmq_for_cluster()

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
    processId: str
    processType: str
    url: str

    class Config:
        json_schema_extra = {
            'example': {
                'processId': '123e4567-e89b-12d3-a456-426614174000',
                'processType': 'APP_REVIEW',
                'url': 'https://example.com/app.apk',
            }
        }


class ScanJobQueued(Schema):
    status: str
    processId: str
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
    host = os.getenv('VALKEY_HOST', 'localhost')
    port = int(os.getenv('VALKEY_PORT', '6379'))
    username = os.getenv('VALKEY_USERNAME', 'default')
    use_iam = should_use_iam_auth()

    try:
        logger.debug(
            f'[REDIS_OPTS] Getting credential for user={username}, host={host}:{port}, '
            f'mode={"IAM_TOKEN" if use_iam else "STATIC_PASSWORD"}')
        password = get_memorydb_auth_token()
        logger.info('[REDIS_OPTS_OK] Credential obtained')
    except Exception as e:
        logger.error(f'[REDIS_OPTS_ERROR] Failed: {type(e).__name__}: {e}', exc_info=True)
        raise

    opts = {
        'host': host,
        'port': port,
        'password': password,
        'username': username,
    }

    if use_iam:
        opts.update({
            'ssl': True,
            'ssl_cert_reqs': None,
            'socket_timeout': 10,
        })

    logger.debug(
        f'[REDIS_CONFIG] host={host}:{port}, username={username}, '
        f'ssl={opts.get("ssl", False)}, cluster_mode={use_iam}')
    return opts


def _build_queue(queue_name: str) -> Queue:
    """Create a BullMQ Queue connected to Redis or MemoryDB cluster."""
    opts = _redis_opts()
    use_iam = should_use_iam_auth()

    if use_iam:
        logger.debug('[REDIS_CONNECT] Creating RedisCluster connection (AWS MemoryDB cluster mode)')
        connection = redis.RedisCluster(
            host=opts['host'],
            port=opts['port'],
            password=opts.get('password'),
            username=opts.get('username'),
            ssl=True,
            ssl_cert_reqs=None,
            socket_timeout=10,
            decode_responses=True,
            skip_full_coverage_check=True,  # MemoryDB doesn't expose full cluster info
        )
        logger.debug('[REDIS_CONNECT_OK] RedisCluster connection created')
    else:
        logger.debug('[REDIS_CONNECT] Creating Redis connection (local/dev mode)')
        connection = opts  # bullmq creates redis.Redis from dict in non-cluster mode

    return Queue(queue_name, {'connection': connection})


def _get_input_queue() -> str:
    # Must match QueueNames.APP_SCANNER_REQUESTS in NestJS (with {} for cluster slot)
    return os.getenv('QUEUE_INPUT', '{app-scanner-requests}')


def _get_output_queue() -> str:
    # Must match QueueNames.APP_SCANNER_RESULTS in NestJS (with {} for cluster slot)
    return os.getenv('QUEUE_OUTPUT', '{app-scanner-results}')


def _ensure_cluster_safe_name(queue_name: str) -> str:
    """Warn if a queue name lacks {} hash tag required for Redis Cluster slot routing."""
    if should_use_iam_auth() and not ('{' in queue_name and '}' in queue_name):
        logger.warning(
            f'[QUEUE_NAME_WARNING] Queue name "{queue_name}" has no {{}} hash tag. '
            'In Redis Cluster mode all BullMQ keys for a queue must map to the same slot. '
            'Wrap the name in braces, e.g. "{%s}". See: https://docs.bullmq.io/guide/redis-tm-hosting/aws-memorydb',
            queue_name,
        )
    return queue_name


async def _push_to_queue(process_id: str, process_type: str, url: str, timeout: int = 30) -> None:
    queue_name = _ensure_cluster_safe_name(_get_input_queue())
    logger.debug(
        f'[ASYNC_PUSH_START] processId={process_id}, processType={process_type}, queue={queue_name}, url={url}, timeout={timeout}s')

    start_time = time.time()

    try:
        q = _build_queue(queue_name)
        logger.debug('[REDIS_CONNECT_OK] Queue object created with BullMQ')
    except Exception as e:
        logger.error(f'[REDIS_CONNECT_ERROR] Failed to create Queue: {type(e).__name__}: {e}')
        raise

    try:
        logger.debug(f'[QUEUE_ADD_START] Adding job to queue "{queue_name}"...')

        # Add timeout protection for queue.add operation
        try:
            job = await asyncio.wait_for(
                q.add('app-binary-scan-requested', {
                    'processId': process_id,
                    'processType': process_type,
                    'url': url,
                }),
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
        'Publishes a new scan job to the BullMQ input queue (`{app-scanner-requests}` by default). '
        'The queue worker will download the APK from `url`, run a static analysis '
        'and publish the result to the output queue (`{app-scanner-results}` by default).'
    ),
    tags=['Queue'],
)
def push_scan_job(request, payload: ScanJobRequest):
    request_id = f"{payload.processId}-{int(time.time()*1000)}"

    logger.info(
        f'[REQUEST_START] request_id={request_id} | processId={payload.processId} | processType={payload.processType} | url={payload.url}')
    logger.debug(
        f'[REQUEST_DETAILS] method={request.method}, path={request.path}, client_ip={request.META.get("REMOTE_ADDR")}')

    queue_name = _get_input_queue()
    start_time = time.time()

    try:
        logger.debug(
            f'[ASYNCIO_RUN_START] request_id={request_id} | Starting async task...')
        asyncio.run(_push_to_queue(payload.processId, payload.processType, payload.url))
        elapsed = time.time() - start_time
        logger.info(
            f'[REQUEST_SUCCESS] request_id={request_id} | Completed in {elapsed:.2f}s | processId={payload.processId}')

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
        processId=payload.processId,
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
    host = os.getenv('VALKEY_HOST', 'localhost')
    port = int(os.getenv('VALKEY_PORT', '6379'))
    return QueueConfig(
        input_queue=_get_input_queue(),
        output_queue=_get_output_queue(),
        valkey_host=host,
        valkey_port=port,
    )
