# -*- coding: utf_8 -*-
"""
Queue Integration API — django-ninja router.

Swagger UI:  /api/queue/docs
OpenAPI JSON: /api/queue/openapi.json
"""

import asyncio
import logging
import os

from ninja import NinjaAPI, Schema
from ninja.responses import codes_4xx, codes_5xx

from bullmq import Queue

logger = logging.getLogger(__name__)

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
    return {
        'host': os.getenv('VALKEY_HOST', 'localhost'),
        'port': int(os.getenv('VALKEY_PORT', '6379')),
        'password': os.getenv('VALKEY_PASSWORD', ''),
        'username': os.getenv('VALKEY_USERNAME', 'default'),
    }


def _get_input_queue() -> str:
    return os.getenv('QUEUE_INPUT', 'APP-SCANN')


def _get_output_queue() -> str:
    return os.getenv('QUEUE_OUTPUT', 'APP-SCANN-RESULT')


async def _push_to_queue(process_id: str, url: str) -> None:
    queue_name = _get_input_queue()
    q = Queue(queue_name, {'connection': _redis_opts()})
    try:
        await q.add('app-binary-scan-requested', {'processID': process_id, 'url': url})
    finally:
        await q.close()


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
    queue_name = _get_input_queue()
    try:
        asyncio.run(_push_to_queue(payload.processID, payload.url))
    except Exception as exc:
        logger.exception('Failed to push job to queue %s', queue_name)
        return 500, ErrorResponse(error='queue_error', message=str(exc))

    logger.info('Pushed job to queue %s | processID=%s | url=%s',
                queue_name, payload.processID, payload.url)
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
