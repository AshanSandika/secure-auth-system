"""Allow-listed security event logging. Never accepts request bodies or secrets."""
from datetime import datetime, timezone
from flask import g, has_request_context, request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session


def install_audit(app, db):
    class AuditEvent(db.Model):
        __tablename__ = 'audit_events'
        id = db.Column(db.Integer, primary_key=True)
        created_at = db.Column(db.DateTime(timezone=True), nullable=False,
                               default=lambda: datetime.now(timezone.utc), index=True)
        event = db.Column(db.String(50), nullable=False, index=True)
        user_id = db.Column(db.Integer, nullable=True)
        source = db.Column(db.String(64), nullable=False)
        endpoint = db.Column(db.String(80), nullable=False)
        status = db.Column(db.Integer, nullable=True)

    allowed = {'profile_updated', 'course_enrolled', 'course_dropped', 'course_created', 'announcement_published', 'register_success', 'register_rejected', 'login_failed', 'login_success',
               'mfa_required', 'mfa_failed', 'mfa_success', 'mfa_enabled',
               'mfa_setup_password_failed', 'recovery_login_success', 'recovery_codes_generated',
               'recovery_generation_failed', 'logout', 'admin_access_denied', 'admin_access_granted',
               'role_set_admin', 'role_set_user', 'rate_limit_exceeded', 'request_rejected'}

    def persist(rows):
        try:
            # Independent transaction: logging never commits pending application changes.
            with Session(db.engine) as log_session:
                log_session.add_all([AuditEvent(**row) for row in rows])
                log_session.commit()
        except SQLAlchemyError:
            # No exception text: DB errors can contain sensitive connection details.
            app.logger.error('Audit storage unavailable; security events were not saved.')

    def record(event, user_id=None):
        if event not in allowed:
            raise ValueError('Unknown audit event')
        row = {'event': event, 'user_id': user_id,
               'source': (request.remote_addr or 'unknown')[:64] if has_request_context() else 'local-cli',
               'endpoint': (request.endpoint or 'unmatched')[:80] if has_request_context() else 'set-role',
               'status': None}
        if has_request_context():
            if not hasattr(g, 'audit_rows'):
                g.audit_rows = []
            g.audit_rows.append(row)
        else:
            persist([row])

    @app.after_request
    def save_request_audit(response):
        if response.status_code == 429:
            record('rate_limit_exceeded')
        elif response.status_code == 400:
            record('request_rejected')
        rows = getattr(g, 'audit_rows', [])
        for row in rows:
            row['status'] = response.status_code
        if rows:
            persist(rows)
        return response

    return AuditEvent, record
