# -*- coding: utf_8 -*-
"""
Custom PostgreSQL backend that refreshes the RDS IAM auth token
on every new connection, preventing failures after token expiry (15 min).
"""
from django.db.backends.postgresql import base


class DatabaseWrapper(base.DatabaseWrapper):

    def get_connection_params(self):
        params = super().get_connection_params()
        try:
            from mobsf.queue_integration.aws_auth import get_rds_auth_token, should_use_iam_auth
            if should_use_iam_auth():
                params['password'] = get_rds_auth_token()
        except Exception:
            pass
        return params
