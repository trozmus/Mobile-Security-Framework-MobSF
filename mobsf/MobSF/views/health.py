"""Readiness / liveness health-check endpoint."""
from django.db import connections
from django.db.utils import OperationalError
from django.http import JsonResponse


def healthz(request):
    try:
        connections['default'].ensure_connection()
    except OperationalError as exc:
        return JsonResponse({'status': 'error', 'db': str(exc)}, status=503)
    return JsonResponse({'status': 'ok'})
