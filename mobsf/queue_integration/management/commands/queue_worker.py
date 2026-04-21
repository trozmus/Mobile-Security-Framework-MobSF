# -*- coding: utf_8 -*-
"""
BullMQ Queue Worker for MobSF.

Listens on the input queue (env: QUEUE_INPUT, default: {app-scanner-requests}),
downloads the APK from the provided URL, performs a static analysis scan using
MobSF internals, and publishes the result to the output queue.

Environment variables:
    VALKEY_HOST      – Redis/Valkey host (default: localhost)
    VALKEY_PORT      – Redis/Valkey port (default: 6379)
    VALKEY_PASSWORD  – Redis/Valkey password (local only)
    VALKEY_USERNAME  – Redis/Valkey username (default: default)
    QUEUE_INPUT      – Input queue  (default: {app-scanner-requests})
    QUEUE_OUTPUT     – Output queue (default: {app-scanner-results})
    QUEUE_ERRORS     – Errors queue (default: {app-scanner-errors})
    NODE_ENV         – local / dev / prod (determines auth method)

Usage:
    python manage.py queue_worker
"""

import asyncio
import io
import logging
import os
from pathlib import Path
from urllib.parse import urlparse

import redis
import redis.asyncio
import requests
from django.conf import settings
from django.core.management.base import BaseCommand

from bullmq import Queue, Worker

from mobsf.queue_integration.aws_auth import (
    get_memorydb_auth_token,
    should_use_iam_auth,
)

try:
    from redis.exceptions import AuthenticationError, ConnectionError as RedisConnectionError
except ImportError:
    class AuthenticationError(Exception):
        pass
    class RedisConnectionError(Exception):
        pass

from mobsf.MobSF.views.scanning import add_to_recent_scan, handle_uploaded_file
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
from mobsf.StaticAnalyzer.views.android.apk import (
    apk_analysis_task,
    initialize_app_dic,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Bullmq cluster patch — same as views.py
# ---------------------------------------------------------------------------

def _patch_bullmq_for_cluster() -> None:
    """Patch bullmq's RedisConnection to accept redis.asyncio.RedisCluster.

    bullmq internally does `import redis.asyncio as redis` and checks
    isinstance(opts, redis.Redis). asyncio.RedisCluster is not a subclass,
    so we add explicit handling here.
    """
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


_patch_bullmq_for_cluster()


# ---------------------------------------------------------------------------
# Queue / connection helpers
# ---------------------------------------------------------------------------

def _get_input_queue() -> str:
    # Must match QueueNames.APP_SCANNER_REQUESTS in NestJS
    return os.getenv('QUEUE_INPUT', '{app-scanner-requests}')


def _get_output_queue() -> str:
    # Must match QueueNames.APP_SCANNER_RESULTS in NestJS
    return os.getenv('QUEUE_OUTPUT', '{app-scanner-results}')


def _get_errors_queue() -> str:
    # Must match QueueNames.APP_SCANNER_ERRORS in NestJS
    return os.getenv('QUEUE_ERRORS', '{app-scanner-errors}')


def _build_connection():
    """Create redis.asyncio.RedisCluster (prod) or return opts dict (local).

    In cluster mode (NODE_ENV=dev/prod) bullmq needs an async Redis client
    so that Script.__call__ returns a coroutine — sync RedisCluster would
    cause 'object str can't be used in await expression'.
    """
    host = os.getenv('VALKEY_HOST', 'localhost')
    port = int(os.getenv('VALKEY_PORT', '6379'))
    username = os.getenv('VALKEY_USERNAME', 'default')
    use_iam = should_use_iam_auth()

    logger.debug(
        '[WORKER_CONN] host=%s:%s, username=%s, mode=%s',
        host, port, username, 'IAM_TOKEN' if use_iam else 'STATIC_PASSWORD',
    )

    password = get_memorydb_auth_token()
    logger.info('[WORKER_CONN] Credential obtained')

    if use_iam:
        logger.debug('[WORKER_CONN] Creating asyncio.RedisCluster (cluster mode)')
        conn = redis.asyncio.RedisCluster(
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
        logger.debug('[WORKER_CONN] asyncio.RedisCluster created')
        return conn
    else:
        logger.debug('[WORKER_CONN] Using dict opts (local Redis)')
        return {
            'host': host,
            'port': port,
            'username': username,
            'password': password,
        }


def _build_queue(queue_name: str) -> Queue:
    conn = _build_connection()
    q = Queue(queue_name, {'connection': conn})
    logger.debug('[WORKER_QUEUE] Queue object created: name=%s', queue_name)
    return q


# ---------------------------------------------------------------------------
# APK helpers
# ---------------------------------------------------------------------------

def _filename_from_url(url: str) -> str:
    path = urlparse(url).path
    name = os.path.basename(path)
    return name if name.lower().endswith('.apk') else 'app.apk'


def _download_apk(url: str) -> tuple[bytes, str]:
    logger.info('[DOWNLOAD] Downloading APK from %s', url)
    resp = requests.get(url, timeout=120, stream=True)
    resp.raise_for_status()
    content = b''.join(resp.iter_content(chunk_size=65536))
    if not content:
        raise ValueError(f'Downloaded file is empty: {url}')
    filename = _filename_from_url(url)
    logger.info('[DOWNLOAD] Downloaded %d bytes as %s', len(content), filename)
    return content, filename


def _run_static_scan(filename: str, apk_bytes: bytes) -> tuple[str, dict]:
    buf = io.BufferedReader(io.BytesIO(apk_bytes))
    checksum = handle_uploaded_file(buf, '.apk')

    add_to_recent_scan({
        'analyzer': 'static_analyzer',
        'status': 'success',
        'hash': checksum,
        'scan_type': 'apk',
        'file_name': filename,
    })

    app_dic = {
        'dir': Path(settings.BASE_DIR),
        'app_name': filename,
        'md5': checksum,
        'app_dir': Path(settings.UPLD_DIR) / checksum,
        'tools_dir': (Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'tools').as_posix(),
        'icon_path': '',
    }
    initialize_app_dic(app_dic, 'apk')

    logger.info('[SCAN] Starting static analysis: file=%s md5=%s', filename, checksum)
    context, err = apk_analysis_task(checksum, app_dic, rescan=False)
    if err:
        raise RuntimeError(f'Static analysis failed: {err}')

    db_entry = StaticAnalyzerAndroid.objects.filter(MD5=checksum)
    if not db_entry.exists():
        raise RuntimeError(f'Analysis completed but no DB entry found for md5={checksum}')

    report = get_context_from_db_entry(db_entry)
    logger.info('[SCAN] Complete: md5=%s', checksum)
    return checksum, report


# ---------------------------------------------------------------------------
# Publish result
# ---------------------------------------------------------------------------

async def _publish(payload: dict, max_retries: int = 2) -> None:
    is_error = payload.get('status') == 'error'
    queue_name = _get_errors_queue() if is_error else _get_output_queue()
    job_name = 'app-binary-scan-error' if is_error else 'app-binary-scan-result'

    logger.debug(
        '[PUBLISH] Publishing job=%s to queue=%s processId=%s',
        job_name, queue_name, payload.get('processId'),
    )

    last_error = None
    for attempt in range(max_retries):
        q = _build_queue(queue_name)
        try:
            job = await q.add(job_name, payload)
            logger.info(
                '[PUBLISH_OK] Published job=%s id=%s to queue=%s processId=%s',
                job_name,
                job.id if hasattr(job, 'id') else 'unknown',
                queue_name,
                payload.get('processId'),
            )
            return
        except (AuthenticationError, RedisConnectionError) as e:
            last_error = e
            logger.warning(
                '[PUBLISH_RETRY] Auth/connection error (attempt %d/%d) queue=%s: %s',
                attempt + 1, max_retries, queue_name, e,
            )
            if attempt < max_retries - 1:
                await asyncio.sleep(1)
        except Exception as e:
            logger.error('[PUBLISH_ERROR] Failed to publish to queue=%s: %s', queue_name, e)
            raise
        finally:
            try:
                await q.close()
            except Exception:
                pass

    logger.error('[PUBLISH_FAILED] Exhausted %d retries. Last error: %s', max_retries, last_error)
    raise last_error


# ---------------------------------------------------------------------------
# Job processor
# ---------------------------------------------------------------------------

async def _process_job(job, token):
    """Process a single input-queue job.

    Expected job.data:
        processId  (str) – process identifier
        processType (str) – process type (e.g. APP_REVIEW)
        url        (str) – publicly accessible URL to the APK file
    """
    logger.info(
        '[JOB_RECEIVED] id=%s name=%s data=%r',
        job.id, job.name, job.data,
    )

    if job.name != 'app-binary-scan-requested':
        logger.warning(
            '[JOB_SKIP] id=%s unexpected name=%r — expected "app-binary-scan-requested"',
            job.id, job.name,
        )
        return

    job_data = job.data.get('jobData', job.data)

    if 'report' in job_data or ('status' in job_data and job_data['status'] in ('success', 'error')):
        logger.warning(
            '[JOB_SKIP] id=%s looks like a result payload (has report/status) — '
            'check that output queue consumers are not re-publishing to input queue',
            job.id,
        )
        return

    # Accept both processId (NestJS convention) and processID (legacy)
    process_id = job_data.get('processId') or job_data.get('processID')
    url = job_data.get('url')

    logger.info(
        '[JOB_START] id=%s processId=%s processType=%s url=%s',
        job.id, process_id, job_data.get('processType'), url,
    )

    if not process_id or not url:
        logger.error(
            '[JOB_INVALID] id=%s missing required fields: processId=%r url=%r — '
            'full data: %r',
            job.id, process_id, url, job_data,
        )
        return

    loop = asyncio.get_event_loop()

    # --- Download ---
    try:
        apk_bytes, filename = await loop.run_in_executor(None, _download_apk, url)
    except Exception as exc:
        logger.error('[JOB_DOWNLOAD_FAIL] id=%s processId=%s url=%s: %s',
                     job.id, process_id, url, exc)
        await _publish({
            'processId': process_id,
            'status': 'error',
            'error': 'download_failed',
            'message': str(exc),
        })
        return

    # --- Scan ---
    try:
        _, report = await loop.run_in_executor(None, _run_static_scan, filename, apk_bytes)
    except Exception as exc:
        logger.error('[JOB_SCAN_FAIL] id=%s processId=%s file=%s: %s',
                     job.id, process_id, filename, exc)
        await _publish({
            'processId': process_id,
            'status': 'error',
            'error': 'scan_failed',
            'message': str(exc),
            'fileName': filename,
        })
        return

    # --- Success ---
    logger.info('[JOB_DONE] id=%s processId=%s file=%s', job.id, process_id, filename)
    await _publish({
        'processId': process_id,
        'status': 'success',
        'fileName': filename,
        'report': report,
    })


# ---------------------------------------------------------------------------
# Worker lifecycle
# ---------------------------------------------------------------------------

async def _run_worker():
    """Start the BullMQ worker. Returns True if restart needed, False on clean stop."""
    input_queue = _get_input_queue()
    output_queue = _get_output_queue()
    errors_queue = _get_errors_queue()
    use_iam = should_use_iam_auth()
    host = os.getenv('VALKEY_HOST', 'localhost')
    port = os.getenv('VALKEY_PORT', '6379')
    prefix = 'bull'

    logger.info('=' * 60)
    logger.info('[WORKER_START] BullMQ Worker starting up')
    logger.info('[WORKER_START] NODE_ENV=%s, auth=%s',
                os.getenv('NODE_ENV', 'local'), 'IAM_TOKEN' if use_iam else 'STATIC_PASSWORD')
    logger.info('[WORKER_START] Redis: %s:%s', host, port)
    logger.info('[WORKER_START] cluster_mode=%s', use_iam)
    logger.info('[WORKER_START] Queues:')
    logger.info('[WORKER_START]   input  = %s', input_queue)
    logger.info('[WORKER_START]   output = %s', output_queue)
    logger.info('[WORKER_START]   errors = %s', errors_queue)
    logger.info('[WORKER_START] Redis keys listened on:')
    logger.info('[WORKER_START]   %s:%s:wait', prefix, input_queue)
    logger.info('[WORKER_START]   %s:%s:active', prefix, input_queue)
    logger.info('[WORKER_START]   %s:%s:delayed', prefix, input_queue)
    logger.info('[WORKER_START] Job name filter: "app-binary-scan-requested"')
    logger.info('=' * 60)

    worker = None
    try:
        logger.info('[WORKER_CONNECT] Obtaining credentials...')
        conn = _build_connection()
        logger.info('[WORKER_CONNECT] Creating BullMQ Worker on queue=%s', input_queue)
        worker = Worker(input_queue, _process_job, {'connection': conn})
        logger.info('[WORKER_READY] Worker is listening. Waiting for jobs...')

        while True:
            await asyncio.sleep(5)
            logger.debug('[WORKER_HEARTBEAT] alive, queue=%s', input_queue)

    except (AuthenticationError, RedisConnectionError) as e:
        logger.warning('[WORKER_AUTH_ERROR] %s — will restart with fresh credentials', e)
        return True
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info('[WORKER_STOP] Shutting down gracefully...')
        return False
    except Exception as e:
        logger.exception('[WORKER_ERROR] Unexpected error: %s', e)
        return True
    finally:
        if worker:
            try:
                await worker.close()
                logger.info('[WORKER_CLOSED] Worker stopped')
            except Exception as e:
                logger.warning('[WORKER_CLOSE_ERROR] %s', e)


async def _run_worker_with_retry():
    while True:
        try:
            should_restart = await _run_worker()
            if not should_restart:
                break
            logger.info('[WORKER_RESTART] Restarting in 2s...')
            await asyncio.sleep(2)
        except Exception as e:
            logger.exception('[WORKER_RESTART_ERROR] %s — retrying in 5s', e)
            await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# Django management command
# ---------------------------------------------------------------------------

class Command(BaseCommand):
    help = 'Start the BullMQ worker (QUEUE_INPUT → QUEUE_OUTPUT).'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS(
            f'Starting BullMQ worker [{_get_input_queue()} → {_get_output_queue()}]'
        ))
        if should_use_iam_auth():
            self.stdout.write(self.style.NOTICE(
                f'IAM auth enabled (NODE_ENV={os.getenv("NODE_ENV")}) — '
                'worker will auto-restart on token expiration'
            ))
        try:
            asyncio.run(_run_worker_with_retry())
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('Worker interrupted.'))
