# -*- coding: utf_8 -*-
"""
Queue Integration API — django-ninja router.

Swagger UI:  /api/queue/docs
OpenAPI JSON: /api/queue/openapi.json
"""

import asyncio
import json
import logging
import os
import time

import redis
from ninja import NinjaAPI, Schema
from ninja.errors import ValidationError as NinjaValidationError
from ninja.responses import codes_4xx, codes_5xx

from bullmq import Queue

from mobsf.queue_integration.aws_auth import (
    get_memorydb_auth_token,
    should_use_iam_auth,
)


def _patch_bullmq_for_cluster() -> None:
    """Patch bullmq for Redis Cluster compatibility.

    1. RedisConnection.__init__: accept redis.asyncio.RedisCluster directly
       (bullmq only checks isinstance(opts, redis.Redis) which fails for cluster).

    2. Worker.extendLocks: bullmq uses a pipeline to batch lock-renewal evalsha
       calls, but Redis Cluster blocks pipelined evalsha across key slots.
       Replace with sequential per-job calls.
    """
    import logging as _logging
    from bullmq.redis_connection import RedisConnection

    if getattr(RedisConnection, '_cluster_patched', False):
        return

    _original_init = RedisConnection.__init__

    def _patched_init(self, redisOpts={}):
        if isinstance(redisOpts, redis.asyncio.RedisCluster):
            self.version = None
            self.conn = redisOpts
        else:
            _original_init(self, redisOpts)

    RedisConnection.__init__ = _patched_init
    RedisConnection._cluster_patched = True

    # Patch Worker.extendLocks to avoid pipelined evalsha (blocked in cluster mode)
    try:
        from bullmq.worker import Worker as _BullWorker
        _patch_logger = _logging.getLogger(__name__)

        async def _cluster_extend_locks(self, jobs):
            for job in jobs:
                try:
                    await self.scripts.extendLock(
                        job.id, self.token, self.opts.get('lockDuration'),
                    )
                except Exception as e:
                    _patch_logger.warning(
                        '[CLUSTER_PATCH] extendLock failed job=%s: %s', job.id, e,
                    )

        _BullWorker.extendLocks = _cluster_extend_locks
    except Exception as e:
        import logging as _l
        _l.getLogger(__name__).warning('[CLUSTER_PATCH] Could not patch Worker.extendLocks: %s', e)


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


def _log_request_body(request, label: str, extra: str = '') -> None:
    try:
        body = json.loads(request.body.decode('utf-8'))
        logger.error('[%s] %s %s | body=%s%s', label, request.method, request.path, json.dumps(body), extra)
    except Exception as parse_err:
        logger.error('[%s] %s %s | body=<unparseable: %s>%s', label, request.method, request.path, parse_err, extra)


@api.exception_handler(NinjaValidationError)
def log_validation_error(request, exc: NinjaValidationError):
    _log_request_body(request, 'VALIDATION_ERROR_422', f' | validation_errors={json.dumps(exc.errors)}')
    raise exc


@api.exception_handler(Exception)
def log_unhandled(request, exc):
    _log_request_body(request, 'REQUEST_EXCEPTION', f' | {type(exc).__name__}: {exc}')
    raise exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ScanJobRequest(Schema):
    appProcessId: str
    appScanExecutionId: str
    processType: str = 'APP_REVIEW'
    url: str

    class Config:
        json_schema_extra = {
            'example': {
                'appProcessId': '123e4567-e89b-12d3-a456-426614174000',
                'appScanExecutionId': '9b628dcf-4128-4e06-9dda-42e8edef1c4f',
                'processType': 'APP_REVIEW',
                'url': 'https://example.com/app.apk',
            }
        }


class ScanJobQueued(Schema):
    status: str
    appProcessId: str
    appScanExecutionId: str
    queue: str


class QueueConfig(Schema):
    input_queue: str
    output_queue: str
    valkey_host: str
    valkey_port: int


class ErrorResponse(Schema):
    error: str
    message: str


class QueueStats(Schema):
    queue: str
    waiting: int
    active: int
    completed: int
    failed: int
    delayed: int
    paused: int


class QueueStatsResponse(Schema):
    queues: list[QueueStats]


class JobSummary(Schema):
    id: str
    name: str
    status: str
    timestamp: int | None
    processedOn: int | None
    finishedOn: int | None
    attemptsMade: int
    failedReason: str | None
    data_keys: list[str]


class JobListResponse(Schema):
    queue: str
    status: str
    total: int
    jobs: list[JobSummary]


class JobActionResponse(Schema):
    job_id: str
    queue: str
    action: str
    status: str


class ScanLogEntry(Schema):
    timestamp: str
    status: str
    exception: str | None


class ScanLogsResponse(Schema):
    checksum: str
    logs: list[ScanLogEntry]


class ActiveScanResponse(Schema):
    jobId: str
    appProcessId: str
    appScanExecutionId: str | None
    startedAt: int
    elapsedSeconds: int


class HealthResponse(Schema):
    status: str
    version: str
    tag: str
    commit: str
    db: str


def _get_commit_hash() -> str:
    return os.getenv('MOBSFSCAN_COMMIT', 'unknown')


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
        logger.debug('[REDIS_CONNECT] Creating asyncio.RedisCluster connection (AWS MemoryDB cluster mode)')
        connection = redis.asyncio.RedisCluster(
            host=opts['host'],
            port=opts['port'],
            password=opts.get('password'),
            username=opts.get('username'),
            ssl=True,
            ssl_cert_reqs=None,
            ssl_check_hostname=False,
            socket_timeout=10,
            decode_responses=True,
            require_full_coverage=False,  # MemoryDB doesn't expose full cluster info
        )
        logger.debug('[REDIS_CONNECT_OK] asyncio.RedisCluster connection created')
    else:
        logger.debug('[REDIS_CONNECT] Creating Redis connection (local/dev mode)')
        connection = opts  # bullmq creates redis.asyncio.Redis from dict in non-cluster mode

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


async def _push_to_queue(process_id: str, scan_execution_id: str, process_type: str, url: str, timeout: int = 30) -> None:
    queue_name = _ensure_cluster_safe_name(_get_input_queue())
    logger.debug(
        f'[ASYNC_PUSH_START] appProcessId={process_id}, appScanExecutionId={scan_execution_id}, processType={process_type}, queue={queue_name}, url={url}, timeout={timeout}s')

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
                    'jobData': {
                        'appProcessId': process_id,
                        'appScanExecutionId': scan_execution_id,
                        'processType': process_type,
                        'url': url,
                    },
                }),
                timeout=timeout
            )
            elapsed = time.time() - start_time
            logger.info(
                f'[QUEUE_ADD_OK] Job added successfully in {elapsed:.2f}s | appProcessId={process_id} | queue={queue_name} | job_id={job.id if hasattr(job, "id") else "unknown"}')
        except asyncio.TimeoutError:
            elapsed = time.time() - start_time
            logger.error(
                f'[QUEUE_ADD_TIMEOUT] Queue add operation timed out after {timeout}s | elapsed={elapsed:.2f}s | appProcessId={process_id} | queue={queue_name}')
            raise TimeoutError(f'Queue add operation timed out after {timeout}s')

    except TimeoutError:
        raise
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(
            f'[QUEUE_ADD_ERROR] Failed after {elapsed:.2f}s: {type(e).__name__}: {e} | appProcessId={process_id}')
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

def _redis_sync_client():
    """Return a sync Redis client — RedisCluster in IAM/cluster mode, Redis otherwise."""
    from mobsf.queue_integration.aws_auth import get_memorydb_auth_token, should_use_iam_auth
    host = os.getenv('VALKEY_HOST', 'localhost')
    port = int(os.getenv('VALKEY_PORT', '6379'))
    username = os.getenv('VALKEY_USERNAME', 'default')
    password = get_memorydb_auth_token()
    if should_use_iam_auth():
        return redis.RedisCluster(
            host=host,
            port=port,
            username=username,
            password=password,
            ssl=True,
            ssl_cert_reqs=None,
            ssl_check_hostname=False,
            socket_timeout=10,
            decode_responses=True,
            require_full_coverage=False,
        )
    return redis.Redis(host=host, port=port, username=username, password=password, decode_responses=True)


def _resolve_checksum(appScanExecutionId: str | None, appProcessId: str | None) -> str | None:
    r = _redis_sync_client()
    try:
        if appScanExecutionId:
            v = r.get(f'mobsf:scan_exec:{appScanExecutionId}')
            if v:
                return v
        if appProcessId:
            v = r.get(f'mobsf:scan_proc:{appProcessId}')
            if v:
                return v
        return None
    finally:
        r.close()


@api.get(
    '/scan/logs',
    response={200: ScanLogsResponse, codes_4xx: ErrorResponse, codes_5xx: ErrorResponse},
    summary='Get scan progress logs',
    description=(
        'Returns MobSF scan stage logs for a given `appScanExecutionId` or `appProcessId`. '
        'Logs are available as soon as the scan starts and are updated in real time. '
        'Requires at least one of the two query parameters.'
    ),
    tags=['Scan'],
)
def get_scan_logs(request, appScanExecutionId: str = None, appProcessId: str = None):
    from mobsf.MobSF.utils import get_scan_logs as _get_scan_logs
    if not appScanExecutionId and not appProcessId:
        return 400, ErrorResponse(
            error='missing_param',
            message='Provide appScanExecutionId or appProcessId',
        )
    try:
        checksum = _resolve_checksum(appScanExecutionId, appProcessId)
    except Exception as exc:
        logger.exception('[SCAN_LOGS_REDIS_ERROR]')
        return 500, ErrorResponse(error='redis_error', message=str(exc))

    if not checksum:
        return 404, ErrorResponse(
            error='not_found',
            message='No scan found for the given ID. Scan may not have started yet or mapping expired.',
        )
    raw_logs = _get_scan_logs(checksum)
    logs = [
        ScanLogEntry(
            timestamp=entry.get('timestamp', ''),
            status=entry.get('status', ''),
            exception=entry.get('exception'),
        )
        for entry in raw_logs
    ]
    return 200, ScanLogsResponse(checksum=checksum, logs=logs)


@api.get(
    '/scan/active',
    response={200: ActiveScanResponse, codes_4xx: ErrorResponse, codes_5xx: ErrorResponse},
    summary='Get currently active scan',
    description='Returns the job ID and process IDs of the scan currently being processed by the worker, or 404 if idle.',
    tags=['Scan'],
)
def get_active_scan(request):
    import json as _json
    import time as _time
    try:
        r = _redis_sync_client()
        raw = r.get('mobsf:active_scan')
        r.close()
    except Exception as exc:
        logger.exception('[ACTIVE_SCAN_REDIS_ERROR]')
        return 500, ErrorResponse(error='redis_error', message=str(exc))

    if not raw:
        return 404, ErrorResponse(error='not_found', message='No scan is currently being processed.')

    try:
        data = _json.loads(raw)
        started_at = data.get('startedAt', 0)
        return 200, ActiveScanResponse(
            jobId=data['jobId'],
            appProcessId=data['appProcessId'],
            appScanExecutionId=data.get('appScanExecutionId'),
            startedAt=started_at,
            elapsedSeconds=int(_time.time()) - started_at,
        )
    except Exception as exc:
        return 500, ErrorResponse(error='parse_error', message=str(exc))


@api.get(
    '/health',
    response={200: HealthResponse, 503: HealthResponse},
    summary='Health check',
    description='Returns service status, version, and database connectivity.',
    tags=['Health'],
    auth=None,
)
def health_check(request):
    from mobsf.MobSF.views.health import _check_db
    ok, db_status = _check_db()
    status = 'ok' if ok else 'error'
    payload = HealthResponse(
        status=status,
        version=api.version,
        tag=os.getenv('MOBSFSCAN_TAG', 'unknown'),
        commit=_get_commit_hash(),
        db=db_status,
    )
    return 503 if status == 'error' else 200, payload


class ClearCacheResponse(Schema):
    deleted_scans: int
    deleted_results: int


@api.delete(
    '/scans/cache',
    response={200: ClearCacheResponse, codes_5xx: ErrorResponse},
    summary='Clear scan cache',
    description='Deletes all entries from RecentScansDB and StaticAnalyzerAndroid so every application is re-scanned from scratch.',
    tags=['Scans'],
)
def clear_scan_cache(request):
    try:
        from mobsf.StaticAnalyzer.models import RecentScansDB, StaticAnalyzerAndroid
        deleted_scans, _ = RecentScansDB.objects.all().delete()
        deleted_results, _ = StaticAnalyzerAndroid.objects.all().delete()
        logger.info('[CACHE_CLEAR] deleted_scans=%d deleted_results=%d', deleted_scans, deleted_results)
        return 200, ClearCacheResponse(deleted_scans=deleted_scans, deleted_results=deleted_results)
    except Exception as exc:
        logger.exception('[CACHE_CLEAR_ERROR]')
        return 500, ErrorResponse(error='cache_clear_error', message=str(exc))


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
    request_id = f"{payload.appProcessId}-{int(time.time()*1000)}"

    logger.info(
        f'[REQUEST_START] request_id={request_id} | appProcessId={payload.appProcessId} | processType={payload.processType} | url={payload.url}')
    logger.debug(
        f'[REQUEST_DETAILS] method={request.method}, path={request.path}, client_ip={request.META.get("REMOTE_ADDR")}')

    queue_name = _get_input_queue()
    start_time = time.time()

    try:
        logger.debug(
            f'[ASYNCIO_RUN_START] request_id={request_id} | Starting async task...')
        asyncio.run(_push_to_queue(payload.appProcessId, payload.appScanExecutionId, payload.processType, payload.url))
        elapsed = time.time() - start_time
        logger.info(
            f'[REQUEST_SUCCESS] request_id={request_id} | Completed in {elapsed:.2f}s | appProcessId={payload.appProcessId}')

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
        appProcessId=payload.appProcessId,
        appScanExecutionId=payload.appScanExecutionId,
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


async def _get_queue_stats(queue_name: str) -> QueueStats:
    q = _build_queue(queue_name)
    try:
        counts = await q.getJobCounts('waiting', 'active', 'completed', 'failed', 'delayed', 'paused')
        return QueueStats(
            queue=queue_name,
            waiting=counts.get('waiting', 0),
            active=counts.get('active', 0),
            completed=counts.get('completed', 0),
            failed=counts.get('failed', 0),
            delayed=counts.get('delayed', 0),
            paused=counts.get('paused', 0),
        )
    finally:
        try:
            await q.close()
        except Exception:
            pass


@api.get(
    '/stats',
    response={200: QueueStatsResponse, codes_5xx: ErrorResponse},
    summary='Get job counts for all queues',
    description='Returns waiting/active/completed/failed/delayed/paused counts for input, output and errors queues.',
    tags=['Queue'],
)
def get_queue_stats(request):
    queue_names = [
        _get_input_queue(),
        _get_output_queue(),
        os.getenv('QUEUE_ERRORS', '{app-scanner-errors}'),
    ]
    try:
        async def _gather():
            return await asyncio.gather(*[_get_queue_stats(q) for q in queue_names])
        stats = asyncio.run(_gather())
        return 200, QueueStatsResponse(queues=list(stats))
    except Exception as exc:
        logger.exception('[STATS_ERROR]')
        return 500, ErrorResponse(error='stats_error', message=str(exc))


def _job_to_summary(job, status: str) -> JobSummary:
    data = job.data or {}
    job_data = data.get('jobData', data)
    return JobSummary(
        id=str(job.id),
        name=job.name or '',
        status=status,
        timestamp=getattr(job, 'timestamp', None),
        processedOn=getattr(job, 'processedOn', None),
        finishedOn=getattr(job, 'finishedOn', None),
        attemptsMade=getattr(job, 'attemptsMade', 0) or 0,
        failedReason=getattr(job, 'failedReason', None),
        data_keys=list(job_data.keys()) if isinstance(job_data, dict) else list(data.keys()),
    )


async def _get_jobs(queue_name: str, status: str, start: int, end: int) -> list[JobSummary]:
    q = _build_queue(queue_name)
    try:
        method_map = {
            'waiting': q.getWaiting,
            'active': q.getActive,
            'completed': q.getCompleted,
            'failed': q.getFailed,
            'delayed': q.getDelayed,
        }
        getter = method_map.get(status)
        if getter is None:
            raise ValueError(f'Unknown status: {status}')
        jobs = await getter(start, end)
        return [_job_to_summary(j, status) for j in jobs]
    finally:
        try:
            await q.close()
        except Exception:
            pass


VALID_STATUSES = {'waiting', 'active', 'completed', 'failed', 'delayed'}
QUEUE_ALIASES = {
    'input': lambda: _get_input_queue(),
    'output': lambda: _get_output_queue(),
    'errors': lambda: os.getenv('QUEUE_ERRORS', '{app-scanner-errors}'),
}


@api.get(
    '/jobs/{queue_name}/{status}',
    response={200: JobListResponse, codes_4xx: ErrorResponse, codes_5xx: ErrorResponse},
    summary='List jobs by queue and status',
    description=(
        'Returns a list of jobs for a given queue and status. '
        'Use queue aliases: `input`, `output`, `errors`. '
        f'Valid statuses: {", ".join(sorted(VALID_STATUSES))}. '
        'Pagination via `start` and `end` (0-based, inclusive).'
    ),
    tags=['Queue'],
)
def list_jobs(request, queue_name: str, status: str, start: int = 0, end: int = 49):
    if status not in VALID_STATUSES:
        return 400, ErrorResponse(
            error='invalid_status',
            message=f'Status must be one of: {", ".join(sorted(VALID_STATUSES))}',
        )
    resolved = QUEUE_ALIASES.get(queue_name, lambda: queue_name)()
    try:
        jobs = asyncio.run(_get_jobs(resolved, status, start, end))
        return 200, JobListResponse(
            queue=resolved,
            status=status,
            total=len(jobs),
            jobs=jobs,
        )
    except ValueError as exc:
        return 400, ErrorResponse(error='invalid_request', message=str(exc))
    except Exception as exc:
        logger.exception('[LIST_JOBS_ERROR] queue=%s status=%s', resolved, status)
        return 500, ErrorResponse(error='list_jobs_error', message=str(exc))


async def _job_action(queue_name: str, job_id: str, action: str) -> JobActionResponse:
    from bullmq import Job
    q = _build_queue(queue_name)
    try:
        job = await Job.fromId(q, job_id)
        if job is None:
            raise ValueError(f'Job {job_id} not found in queue {queue_name}')
        if action == 'retry':
            await job.retry()
        elif action == 'remove':
            await job.remove()
        else:
            raise ValueError(f'Unknown action: {action}')
        return JobActionResponse(job_id=job_id, queue=queue_name, action=action, status='ok')
    finally:
        try:
            await q.close()
        except Exception:
            pass


@api.post(
    '/jobs/{queue_name}/{job_id}/retry',
    response={200: JobActionResponse, codes_4xx: ErrorResponse, codes_5xx: ErrorResponse},
    summary='Retry a job',
    description=(
        'Moves a job back to `waiting` so it can be picked up again by the worker. '
        'Use this to recover stalled `active` or `failed` jobs. '
        'Use queue aliases: `input`, `output`, `errors`.'
    ),
    tags=['Queue'],
)
def retry_job(request, queue_name: str, job_id: str):
    resolved = QUEUE_ALIASES.get(queue_name, lambda: queue_name)()
    try:
        result = asyncio.run(_job_action(resolved, job_id, 'retry'))
        logger.info('[JOB_RETRY] queue=%s job_id=%s', resolved, job_id)
        return 200, result
    except ValueError as exc:
        return 404, ErrorResponse(error='not_found', message=str(exc))
    except Exception as exc:
        logger.exception('[JOB_RETRY_ERROR] queue=%s job_id=%s', resolved, job_id)
        return 500, ErrorResponse(error='retry_error', message=str(exc))


@api.delete(
    '/jobs/{queue_name}/{job_id}',
    response={200: JobActionResponse, codes_4xx: ErrorResponse, codes_5xx: ErrorResponse},
    summary='Remove a job',
    description=(
        'Permanently removes a job from the queue regardless of its current status. '
        'Use this to clean up stuck `active` jobs after a worker crash. '
        'Use queue aliases: `input`, `output`, `errors`.'
    ),
    tags=['Queue'],
)
def remove_job(request, queue_name: str, job_id: str):
    resolved = QUEUE_ALIASES.get(queue_name, lambda: queue_name)()
    try:
        result = asyncio.run(_job_action(resolved, job_id, 'remove'))
        logger.info('[JOB_REMOVE] queue=%s job_id=%s', resolved, job_id)
        return 200, result
    except ValueError as exc:
        return 404, ErrorResponse(error='not_found', message=str(exc))
    except Exception as exc:
        logger.exception('[JOB_REMOVE_ERROR] queue=%s job_id=%s', resolved, job_id)
        return 500, ErrorResponse(error='remove_error', message=str(exc))
