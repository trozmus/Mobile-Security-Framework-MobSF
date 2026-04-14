#!/bin/bash
set -e

# Run Django migrations
python3 manage.py makemigrations
python3 manage.py makemigrations StaticAnalyzer
python3 manage.py migrate

set +e
python3 manage.py createsuperuser --noinput --email ""
set -e
python3 manage.py create_roles

# Start supervisord which manages gunicorn + queue_worker
exec supervisord -n -c /etc/supervisor/conf.d/mobsf.conf
