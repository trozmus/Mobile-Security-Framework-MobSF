# -*- coding: utf_8 -*-
"""
BullMQ Queue Worker for MobSF.

Listens on the input queue (env: QUEUE_INPUT, default: APP-SCANN),
downloads the APK from the provided URL, performs a static analysis
scan using MobSF internals, and publishes the result or error event
to the output queue (env: QUEUE_OUTPUT, default: APP-SCANN-RESULT).

Environment variables:
    VALKEY_HOST      – Redis/Valkey host (default: localhost)
    VALKEY_PORT      – Redis/Valkey port (default: 6379)
    VALKEY_PASSWORD  – Redis/Valkey password (default: "")
    VALKEY_USERNAME  – Redis/Valkey username (default: default)
    QUEUE_INPUT      – Name of the input queue  (default: APP-SCANN)
    QUEUE_OUTPUT     – Name of the output queue (default: APP-SCANN-RESULT)

Usage:
    python manage.py queue_worker
"""

import asyncio
import io
import logging
import os
from pathlib import Path
from urllib.parse import urlparse

import requests
from django.conf import settings
from django.core.management.base import BaseCommand

from bullmq import Queue, Worker

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


def _get_input_queue() -> str:
    return os.getenv('QUEUE_INPUT', 'APP-SCANN')


def _get_output_queue() -> str:
    return os.getenv('QUEUE_OUTPUT', 'APP-SCANN-RESULT')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redis_opts() -> dict:
    """Build connection options for BullMQ from environment variables."""
    return {
        'host': os.getenv('VALKEY_HOST', 'localhost'),
        'port': int(os.getenv('VALKEY_PORT', '6379')),
        'password': os.getenv('VALKEY_PASSWORD', ''),
        'username': os.getenv('VALKEY_USERNAME', 'default'),
    }


def _filename_from_url(url: str) -> str:
    """Extract filename from URL, falling back to 'app.apk'."""
    path = urlparse(url).path
    name = os.path.basename(path)
    if name.lower().endswith('.apk'):
        return name
    return 'app.apk'


def _download_apk(url: str) -> tuple[bytes, str]:
    """Download the APK file at *url*.

    Returns:
        (raw_bytes, filename)

    Raises:
        requests.HTTPError: on non-2xx HTTP response
        requests.ConnectionError / requests.Timeout: on network issues
    """
    logger.info('Downloading APK from %s', url)
    resp = requests.get(url, timeout=120, stream=True)
    resp.raise_for_status()
    content = b''.join(resp.iter_content(chunk_size=65536))
    if not content:
        raise ValueError(f'Downloaded file is empty: {url}')
    filename = _filename_from_url(url)
    logger.info('Downloaded %d bytes as %s', len(content), filename)
    return content, filename


def _run_static_scan(filename: str, apk_bytes: bytes) -> tuple[str, dict]:
    """Store the APK in MobSF and run a synchronous static analysis.

    Returns:
        (checksum, report_dict)

    Raises:
        RuntimeError: if analysis fails or DB entry is missing after scan
    """
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
        'tools_dir': (
            Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'tools'
        ).as_posix(),
        'icon_path': '',
    }
    initialize_app_dic(app_dic, 'apk')

    logger.info('Starting static analysis for %s (md5=%s)', filename, checksum)
    context, err = apk_analysis_task(checksum, app_dic, rescan=False)
    if err:
        raise RuntimeError(f'Static analysis failed: {err}')

    db_entry = StaticAnalyzerAndroid.objects.filter(MD5=checksum)
    if not db_entry.exists():
        raise RuntimeError(
            f'Analysis completed but no DB entry found for md5={checksum}'
        )
    report = get_context_from_db_entry(db_entry)
    logger.info('Static analysis complete for md5=%s', checksum)
    return checksum, report


async def _publish(payload: dict) -> None:
    """Publish *payload* to the output queue."""
    output_queue_name = _get_output_queue()
    result_queue = Queue(output_queue_name, {'connection': _redis_opts()})
    try:
        await result_queue.add('scan-result', payload)
        logger.info('Published to queue "%s": processID=%s status=%s',
                    output_queue_name, payload.get('processID'), payload.get('status'))
    finally:
        await result_queue.close()


# ---------------------------------------------------------------------------
# BullMQ job processor
# ---------------------------------------------------------------------------

async def _process_job(job, token):
    """Process a single input-queue job.

    Expected job.data keys:
        processID (str) – caller-supplied process identifier
        url       (str) – publicly accessible URL to the APK file

    Publishes to output queue:
        On success:
            { processID, status: "success", fileName, report }
        On download error:
            { processID, status: "error", error: "download_failed", message }
        On scan error:
            { processID, status: "error", error: "scan_failed", message, fileName }
    """
    process_id = job.data.get('processID')
    url = job.data.get('url')

    if not process_id or not url:
        msg = (f'Job {job.id} is missing required fields: '
               f'processID={process_id!r}, url={url!r}')
        logger.error(msg)
        raise ValueError(msg)

    logger.info('Received job %s | processID=%s | url=%s', job.id, process_id, url)

    loop = asyncio.get_event_loop()

    # --- Download APK ---
    try:
        apk_bytes, filename = await loop.run_in_executor(None, _download_apk, url)
    except Exception as exc:
        logger.error('Download failed for processID=%s url=%s: %s',
                     process_id, url, exc)
        await _publish({
            'processID': process_id,
            'status': 'error',
            'error': 'download_failed',
            'message': str(exc),
        })
        return

    # --- Static analysis ---
    try:
        _, report = await loop.run_in_executor(
            None, _run_static_scan, filename, apk_bytes
        )
    except Exception as exc:
        logger.error('Scan failed for processID=%s file=%s: %s',
                     process_id, filename, exc)
        await _publish({
            'processID': process_id,
            'status': 'error',
            'error': 'scan_failed',
            'message': str(exc),
            'fileName': filename,
        })
        return

    # --- Publish success ---
    await _publish({
        'processID': process_id,
        'status': 'success',
        'fileName': filename,
        'report': report,
    })


# ---------------------------------------------------------------------------
# Worker lifecycle
# ---------------------------------------------------------------------------

async def _run_worker():
    """Start the BullMQ worker and block until interrupted."""
    opts = _redis_opts()
    input_queue_name = _get_input_queue()
    logger.info(
        'Connecting to Valkey at %s:%s as user %s',
        opts['host'], opts['port'], opts['username'],
    )
    logger.info(
        'Input queue: "%s" → Output queue: "%s"',
        input_queue_name, _get_output_queue(),
    )
    worker = Worker(input_queue_name, _process_job, {'connection': opts})
    logger.info('Worker listening. Press Ctrl+C to stop.')
    try:
        while True:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info('Shutting down worker…')
    finally:
        await worker.close()
        logger.info('Worker stopped.')


# ---------------------------------------------------------------------------
# Django management command
# ---------------------------------------------------------------------------

class Command(BaseCommand):
    help = (
        'Start the BullMQ worker. Input/output queue names are read from '
        'QUEUE_INPUT and QUEUE_OUTPUT environment variables.'
    )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS(
            f'Starting BullMQ queue worker '
            f'[{_get_input_queue()} → {_get_output_queue()}]…'
        ))
        try:
            asyncio.run(_run_worker())
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('Worker interrupted by user.'))
