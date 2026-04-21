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

import boto3
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
from mobsf.StaticAnalyzer.models import RecentScansDB, StaticAnalyzerAndroid
from mobsf.StaticAnalyzer.views.android.apk import (
    apk_analysis_task,
    initialize_app_dic,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry,
)
from mobsf.StaticAnalyzer.views.common.appsec import get_android_dashboard
from mobsf.StaticAnalyzer.views.common.shared_func import get_avg_cvss

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Bullmq cluster patch — same as views.py
# ---------------------------------------------------------------------------

def _patch_bullmq_for_cluster() -> None:
    """Patch bullmq for Redis Cluster compatibility.

    1. RedisConnection.__init__: accept redis.asyncio.RedisCluster directly
       (bullmq only checks isinstance(opts, redis.Redis) which fails for cluster).

    2. Worker.extendLocks: bullmq uses a pipeline to batch lock-renewal evalsha
       calls, but Redis Cluster blocks pipelined evalsha across key slots.
       Replace with sequential per-job calls.
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

    # Patch Worker.extendLocks to avoid pipelined evalsha (blocked in cluster mode)
    try:
        from bullmq.worker import Worker as _BullWorker

        async def _cluster_extend_locks(self, jobs):
            for job in jobs:
                try:
                    await self.scripts.extendLock(
                        job.id, self.token, self.opts.get('lockDuration'),
                    )
                except Exception as e:
                    logger.warning(
                        '[CLUSTER_PATCH] extendLock failed job=%s: %s', job.id, e,
                    )

        _BullWorker.extendLocks = _cluster_extend_locks
    except Exception as e:
        logger.warning('[CLUSTER_PATCH] Could not patch Worker.extendLocks: %s', e)


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

    NOTE: Worker passes this to RedisConnection twice (redisConnection +
    blockingRedisConnection), so both share the same cluster object.
    """
    host = os.getenv('VALKEY_HOST', 'localhost')
    port = int(os.getenv('VALKEY_PORT', '6379'))
    username = os.getenv('VALKEY_USERNAME', 'default')
    use_iam = should_use_iam_auth()

    logger.info(
        '[CONN_BUILD] host=%s:%s username=%s ssl=%s mode=%s',
        host, port, username, use_iam, 'IAM_TOKEN' if use_iam else 'STATIC_PASSWORD',
    )

    logger.info('[CONN_BUILD] Fetching auth credential...')
    password = get_memorydb_auth_token()
    logger.info('[CONN_BUILD] Credential obtained (length=%d chars)', len(password) if password else 0)

    if use_iam:
        logger.info('[CONN_BUILD] Creating redis.asyncio.RedisCluster...')
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
        logger.info('[CONN_BUILD] redis.asyncio.RedisCluster object created (lazy — connects on first command)')
        return conn
    else:
        logger.info('[CONN_BUILD] Using dict opts (local Redis, bullmq will create asyncio.Redis)')
        return {
            'host': host,
            'port': port,
            'username': username,
            'password': password,
        }


async def _ping_connection(conn) -> bool:
    """Send PING to verify the connection is reachable. Logs result."""
    try:
        if isinstance(conn, redis.asyncio.RedisCluster):
            result = await conn.ping()
        elif isinstance(conn, dict):
            test = redis.asyncio.Redis(**conn, decode_responses=True)
            result = await test.ping()
            await test.aclose()
        else:
            result = await conn.ping()
        logger.info('[CONN_PING] PING → %s', result)
        return True
    except Exception as e:
        logger.error('[CONN_PING] PING failed: %s: %s', type(e).__name__, e)
        return False


async def _diagnose_queue(conn, queue_name: str) -> None:
    """Inspect actual Redis keys for the queue and log their state.

    Helps diagnose why jobs are not being picked up:
    - shows how many jobs are in each list/set
    - verifies the key prefix matches what the worker listens on
    - checks whether the marker key (used by bzpopmin) exists
    """
    prefix = 'bull'
    base = f'{prefix}:{queue_name}'
    keys_to_check = {
        'wait':     f'{base}:wait',
        'active':   f'{base}:active',
        'delayed':  f'{base}:delayed',
        'failed':   f'{base}:failed',
        'completed':f'{base}:completed',
        'marker':   f'{base}:marker',
        'id':       f'{base}:id',
        'meta':     f'{base}:meta',
    }

    logger.info('[QUEUE_DIAG] Inspecting queue: %s', queue_name)
    logger.info('[QUEUE_DIAG] Expected Redis key prefix: "%s"', base)

    try:
        for name, key in keys_to_check.items():
            try:
                key_type = await conn.type(key)
                if key_type == 'none':
                    logger.info('[QUEUE_DIAG]   %-12s %-50s → does not exist', name, key)
                elif key_type == 'list':
                    count = await conn.llen(key)
                    logger.info('[QUEUE_DIAG]   %-12s %-50s → list, %d items', name, key, count)
                elif key_type == 'zset':
                    count = await conn.zcard(key)
                    logger.info('[QUEUE_DIAG]   %-12s %-50s → zset, %d items', name, key, count)
                elif key_type == 'string':
                    val = await conn.get(key)
                    logger.info('[QUEUE_DIAG]   %-12s %-50s → string, value=%r', name, key, val)
                else:
                    logger.info('[QUEUE_DIAG]   %-12s %-50s → %s', name, key, key_type)
            except Exception as e:
                logger.warning('[QUEUE_DIAG]   %-12s %-50s → ERROR: %s', name, key, e)

        # Show first 3 job IDs from wait list to confirm format
        wait_key = keys_to_check['wait']
        try:
            job_ids = await conn.lrange(wait_key, 0, 2)
            if job_ids:
                logger.info('[QUEUE_DIAG] First job IDs in wait: %s', job_ids)
            else:
                logger.info('[QUEUE_DIAG] wait list is empty — no jobs waiting')
        except Exception as e:
            logger.warning('[QUEUE_DIAG] Could not read wait list: %s', e)

    except Exception as e:
        logger.error('[QUEUE_DIAG] Diagnostics failed: %s: %s', type(e).__name__, e)


def _build_queue(queue_name: str) -> Queue:
    conn = _build_connection()
    q = Queue(queue_name, {'connection': conn})
    logger.debug('[WORKER_QUEUE] Queue object created: name=%s', queue_name)
    return q


# ---------------------------------------------------------------------------
# APK helpers
# ---------------------------------------------------------------------------

def _filename_from_path(path: str) -> str:
    name = os.path.basename(path)
    return name if name.lower().endswith('.apk') else 'app.apk'


def _parse_s3_url(url: str) -> tuple[str, str] | None:
    """Return (bucket, key) for s3:// or https://*.s3.*.amazonaws.com/* URLs, else None."""
    parsed = urlparse(url)
    if parsed.scheme == 's3':
        bucket, key = parsed.netloc, parsed.path.lstrip('/')
        logger.debug('[S3_URL_PARSE] scheme=s3 bucket=%s key=%s', bucket, key)
        return bucket, key
    if parsed.scheme in ('https', 'http') and parsed.hostname and '.s3.' in parsed.hostname:
        bucket = parsed.hostname.split('.s3.')[0]
        key = parsed.path.lstrip('/')
        logger.debug('[S3_URL_PARSE] scheme=https bucket=%s key=%s', bucket, key)
        return bucket, key
    logger.debug('[S3_URL_PARSE] url=%s is not an S3 URL, using HTTP download', url)
    return None


def _download_apk_s3(bucket: str, key: str) -> tuple[bytes, str]:
    import time
    region = os.getenv('AWS_REGION', 'eu-central-1')
    logger.info('[DOWNLOAD_S3] Starting: bucket=%s key=%s region=%s', bucket, key, region)
    t0 = time.time()
    try:
        s3 = boto3.client('s3', region_name=region)
        logger.debug('[DOWNLOAD_S3] boto3 client created, calling download_fileobj...')
        buf = io.BytesIO()
        s3.download_fileobj(bucket, key, buf)
        content = buf.getvalue()
        if not content:
            raise ValueError(f'Downloaded file is empty: s3://{bucket}/{key}')
        filename = _filename_from_path(key)
        logger.info('[DOWNLOAD_S3_OK] bucket=%s key=%s size=%d bytes filename=%s elapsed=%.2fs',
                    bucket, key, len(content), filename, time.time() - t0)
        return content, filename
    except Exception as e:
        logger.error('[DOWNLOAD_S3_FAIL] bucket=%s key=%s elapsed=%.2fs error=%s: %s',
                     bucket, key, time.time() - t0, type(e).__name__, e)
        raise


def _download_apk(url: str) -> tuple[bytes, str]:
    import time
    logger.info('[DOWNLOAD] url=%s', url)
    s3_loc = _parse_s3_url(url)
    if s3_loc:
        return _download_apk_s3(*s3_loc)
    t0 = time.time()
    logger.info('[DOWNLOAD_HTTP] Starting HTTP download: url=%s', url)
    try:
        resp = requests.get(url, timeout=120, stream=True)
        logger.debug('[DOWNLOAD_HTTP] HTTP %d for url=%s', resp.status_code, url)
        resp.raise_for_status()
        content = b''.join(resp.iter_content(chunk_size=65536))
        if not content:
            raise ValueError(f'Downloaded file is empty: {url}')
        filename = _filename_from_path(urlparse(url).path)
        logger.info('[DOWNLOAD_HTTP_OK] url=%s size=%d bytes filename=%s elapsed=%.2fs',
                    url, len(content), filename, time.time() - t0)
        return content, filename
    except Exception as e:
        logger.error('[DOWNLOAD_HTTP_FAIL] url=%s elapsed=%.2fs error=%s: %s',
                     url, time.time() - t0, type(e).__name__, e)
        raise


def _generate_pdf(checksum: str) -> bytes | None:
    """Generate PDF report for a completed scan. Returns PDF bytes or None on failure."""
    try:
        import pdfkit
        import platform
        from django.template.loader import get_template
        from mobsf.MobSF.utils import upstream_proxy

        static_db = StaticAnalyzerAndroid.objects.filter(MD5=checksum)
        if not static_db.exists():
            logger.error('[PDF_GEN] No DB entry for md5=%s', checksum)
            return None

        logger.info('[PDF_GEN] Building context for md5=%s', checksum)
        context = get_context_from_db_entry(static_db)
        context['average_cvss'] = get_avg_cvss(context['code_analysis'])
        context['appsec'] = get_android_dashboard(static_db)
        context['virus_total'] = None

        proto = 'file:///' if platform.system() == 'Windows' else 'file://'
        host_os = 'windows' if platform.system() == 'Windows' else 'nix'
        context['base_url'] = proto + settings.BASE_DIR
        context['dwd_dir'] = proto + settings.DWD_DIR
        context['host_os'] = host_os

        try:
            context['timestamp'] = RecentScansDB.objects.get(MD5=checksum).TIMESTAMP
        except RecentScansDB.DoesNotExist:
            context['timestamp'] = None

        options = {
            'page-size': 'Letter',
            'quiet': '',
            'enable-local-file-access': '',
            'no-collate': '',
            'margin-top': '0.50in',
            'margin-right': '0.50in',
            'margin-bottom': '0.50in',
            'margin-left': '0.50in',
            'encoding': 'UTF-8',
            'orientation': 'Landscape',
            'custom-header': [('Accept-Encoding', 'gzip')],
            'no-outline': None,
        }
        proxies, _ = upstream_proxy('https')
        if proxies.get('https'):
            options['proxy'] = proxies['https']

        template = get_template('pdf/android_report.html')
        html = template.render(context)
        logger.info('[PDF_GEN] Rendering PDF for md5=%s', checksum)
        pdf_bytes = pdfkit.from_string(html, False, options=options)
        logger.info('[PDF_GEN_OK] md5=%s size=%d bytes', checksum, len(pdf_bytes))
        return pdf_bytes
    except ImportError:
        logger.warning('[PDF_GEN] pdfkit/wkhtmltopdf not available — skipping PDF generation')
        return None
    except Exception as e:
        logger.error('[PDF_GEN_FAIL] md5=%s error=%s: %s', checksum, type(e).__name__, e)
        return None


def _upload_pdf_to_s3(pdf_bytes: bytes, source_url: str, checksum: str) -> str | None:
    """Upload PDF bytes to S3 in the same directory as the source APK.

    Returns the S3 URI of the uploaded PDF or None on failure.
    """
    s3_loc = _parse_s3_url(source_url)
    if not s3_loc:
        logger.info('[PDF_UPLOAD] Source URL is not S3 — skipping PDF upload')
        return None

    bucket, apk_key = s3_loc
    apk_dir = os.path.dirname(apk_key)
    apk_basename = os.path.splitext(os.path.basename(apk_key))[0]
    pdf_filename = f'{apk_basename}.pdf'
    pdf_key = f'{apk_dir}/{pdf_filename}' if apk_dir else pdf_filename
    region = os.getenv('AWS_REGION', 'eu-central-1')

    logger.info('[PDF_UPLOAD] Uploading PDF to s3://%s/%s', bucket, pdf_key)
    try:
        s3 = boto3.client('s3', region_name=region)
        s3.put_object(
            Bucket=bucket,
            Key=pdf_key,
            Body=pdf_bytes,
            ContentType='application/pdf',
        )
        s3_uri = f's3://{bucket}/{pdf_key}'
        logger.info('[PDF_UPLOAD_OK] Uploaded PDF to %s size=%d bytes', s3_uri, len(pdf_bytes))
        return s3_uri
    except Exception as e:
        logger.error('[PDF_UPLOAD_FAIL] bucket=%s key=%s error=%s: %s',
                     bucket, pdf_key, type(e).__name__, e)
        return None


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

    # Cache hit — skip full scan if result already in DB
    db_entry = StaticAnalyzerAndroid.objects.filter(MD5=checksum)
    db_count = db_entry.count()
    logger.info('[SCAN_CACHE_CHECK] md5=%s db_count=%d', checksum, db_count)
    if db_count > 0:
        logger.info('[SCAN_CACHE_HIT] md5=%s already in DB, skipping scan', checksum)
        report = get_context_from_db_entry(db_entry)
        return checksum, report
    logger.info('[SCAN_CACHE_MISS] md5=%s not in DB, running full scan', checksum)

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
    import time
    job_start = time.time()

    logger.info('─' * 50)
    logger.info('[JOB_DEQUEUED] id=%s name=%s attempts=%s timestamp=%s',
                job.id, job.name,
                job.opts.get('attempts', '?'),
                job.timestamp)
    logger.info('[JOB_DATA] id=%s data=%r', job.id, job.data)

    if job.name != 'app-binary-scan-requested':
        logger.warning(
            '[JOB_SKIP] id=%s unexpected name=%r — expected "app-binary-scan-requested"',
            job.id, job.name,
        )
        return

    job_data = job.data.get('jobData', job.data)
    logger.debug('[JOB_PARSED] id=%s job_data keys=%s', job.id, list(job_data.keys()))

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
    process_type = job_data.get('processType', '?')

    if not process_id or not url:
        logger.error(
            '[JOB_INVALID] id=%s missing required fields: processId=%r url=%r — full data: %r',
            job.id, process_id, url, job_data,
        )
        return

    logger.info('[JOB_START] id=%s processId=%s processType=%s url=%s',
                job.id, process_id, process_type, url)

    loop = asyncio.get_event_loop()

    # --- Download ---
    t0 = time.time()
    logger.info('[JOB_DOWNLOAD] id=%s Starting download from %s', job.id, url)
    try:
        apk_bytes, filename = await loop.run_in_executor(None, _download_apk, url)
        logger.info('[JOB_DOWNLOAD_OK] id=%s file=%s size=%d bytes elapsed=%.2fs',
                    job.id, filename, len(apk_bytes), time.time() - t0)
    except Exception as exc:
        logger.error('[JOB_DOWNLOAD_FAIL] id=%s processId=%s url=%s elapsed=%.2fs error=%s: %s',
                     job.id, process_id, url, time.time() - t0, type(exc).__name__, exc)
        await _publish({
            'processId': process_id,
            'status': 'error',
            'error': 'download_failed',
            'message': str(exc),
        })
        return

    # --- Scan ---
    t0 = time.time()
    logger.info('[JOB_SCAN] id=%s Starting static analysis: file=%s size=%d bytes',
                job.id, filename, len(apk_bytes))
    try:
        checksum, report = await loop.run_in_executor(None, _run_static_scan, filename, apk_bytes)
        logger.info('[JOB_SCAN_OK] id=%s file=%s elapsed=%.2fs', job.id, filename, time.time() - t0)
    except Exception as exc:
        logger.error('[JOB_SCAN_FAIL] id=%s processId=%s file=%s elapsed=%.2fs error=%s: %s',
                     job.id, process_id, filename, time.time() - t0, type(exc).__name__, exc)
        await _publish({
            'processId': process_id,
            'status': 'error',
            'error': 'scan_failed',
            'message': str(exc),
            'fileName': filename,
        })
        return

    # --- Generate and upload PDF ---
    pdf_s3_uri = None
    t0 = time.time()
    logger.info('[JOB_PDF] id=%s Generating PDF report...', job.id)
    pdf_bytes = await loop.run_in_executor(None, _generate_pdf, checksum)
    if pdf_bytes:
        logger.info('[JOB_PDF] id=%s PDF generated in %.2fs, uploading to S3...', job.id, time.time() - t0)
        pdf_s3_uri = await loop.run_in_executor(None, _upload_pdf_to_s3, pdf_bytes, url, checksum)
    else:
        logger.warning('[JOB_PDF] id=%s PDF generation failed or skipped', job.id)

    # --- Success ---
    total = time.time() - job_start
    logger.info('[JOB_DONE] id=%s processId=%s file=%s pdf=%s total_elapsed=%.2fs',
                job.id, process_id, filename, pdf_s3_uri or 'none', total)
    logger.info('─' * 50)
    await _publish({
        'processId': process_id,
        'status': 'success',
        'fileName': filename,
        'report': report,
        'pdfReportUrl': pdf_s3_uri,
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
        logger.info('[WORKER_CONNECT] Step 1/3: Building Redis connection...')
        conn = _build_connection()

        logger.info('[WORKER_CONNECT] Step 2/3: Testing connection with PING...')
        ping_ok = await _ping_connection(conn)
        if not ping_ok:
            logger.error('[WORKER_CONNECT] PING failed — Redis unreachable, aborting start')
            return True

        await _diagnose_queue(conn, input_queue)

        logger.info('[WORKER_CONNECT] Step 3/3: Creating BullMQ Worker on queue=%s', input_queue)
        # lockDuration: 20 min — longer than worst-case scan time.
        # lockRenewTime: renew at half lockDuration (default behaviour).
        # This prevents the job from moving back to waiting during long scans.
        worker = Worker(input_queue, _process_job, {
            'connection': conn,
            'lockDuration': 45 * 60 * 1000,  # 45 minutes in ms
        })
        logger.info('[WORKER_READY] ✓ Worker is live and listening for jobs on queue=%s', input_queue)
        logger.info('[WORKER_READY] Watching Redis keys: bull:%s:wait / :active / :delayed', input_queue)

        while True:
            await asyncio.sleep(15)
            logger.debug('[WORKER_HEARTBEAT] alive queue=%s', input_queue)

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
