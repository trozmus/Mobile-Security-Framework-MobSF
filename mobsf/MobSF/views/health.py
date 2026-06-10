"""Readiness / liveness health-check endpoint."""
from django.db import connections
from django.db.utils import DatabaseError, OperationalError
from django.http import JsonResponse


def _check_db():
    """Return (ok: bool, message: str). Verifies connectivity and migrations."""
    try:
        conn = connections['default']
        conn.ensure_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_name = 'StaticAnalyzer_recentscansdb'"
            )
            if not cursor.fetchone():
                return False, 'migrations not applied (StaticAnalyzer_recentscansdb missing)'
    except (OperationalError, DatabaseError) as exc:
        return False, str(exc)
    return True, 'ok'


def healthz(request):
    ok, message = _check_db()
    if not ok:
        return JsonResponse({'status': 'error', 'db': message}, status=503)
    return JsonResponse({'status': 'ok', 'db': message})
