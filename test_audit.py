"""Audit visibility, event coverage and secret-exclusion checks."""
import os
import re
import secrets
from types import SimpleNamespace
from unittest.mock import patch

import pyotp
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

os.environ.setdefault('SECRET_KEY', secrets.token_hex(32))
os.environ.setdefault('TOTP_ENCRYPTION_KEY', Fernet.generate_key().decode())
os.environ['AUTH_DATABASE_URI'] = 'sqlite://'
from app import app, db, User, AuditEvent, limiter


def test_audit_security():
    app.config['TESTING'] = True
    password = 'Audit password secret 827364!'
    bad_password = 'Incorrect secret 847363!'
    secret = pyotp.random_base32()
    cipher = Fernet(app.config['TOTP_ENCRYPTION_KEY'])
    encrypted = cipher.encrypt(secret.encode()).decode()
    password_hash = generate_password_hash(password)
    with app.app_context():
        db.drop_all()
        db.create_all()
        db.session.add(User(email='admin@example.com', password_hash=password_hash,
            role='admin', mfa_enabled=True, totp_secret_encrypted=encrypted))
        db.session.commit()
    limiter.reset()
    client = app.test_client()
    def token(path):
        r = client.get(path)
        assert r.status_code == 200
        return re.search(r'name="csrf_token"[^>]*value="([^"]+)"', r.text).group(1)
    def post(path, data):
        return client.post(path, data={**data, 'csrf_token': token(path)})
    def logout():
        return client.post('/logout', data={'csrf_token': token('/dashboard')})
    assert client.get('/admin/logs').status_code == 302
    credentials = {'email': 'user@example.com', 'password': password}
    assert post('/register', {**credentials, 'confirm_password': password}).status_code == 302
    assert post('/login', {**credentials, 'password': bad_password}).status_code == 401
    assert post('/login', credentials).status_code == 302
    assert client.get('/admin/logs').status_code == 403
    assert logout().status_code == 302
    with patch('mfa.time', SimpleNamespace(time=lambda: 1800000000)):
        assert post('/login', {'email': 'admin@example.com', 'password': password}).status_code == 302
        code = pyotp.TOTP(secret).at(1800000000)
        wrong_code = f'{(int(code) + 1) % 1000000:06d}'
        assert 'Invalid' in post('/mfa/verify', {'code': wrong_code}).text
        assert post('/mfa/verify', {'code': code}).status_code == 302
        r = client.get('/admin/logs')
        assert r.status_code == 200 and 'login_failed' in r.text
        assert r.headers['Cache-Control'] == 'no-store'
        assert client.get('/admin/logs?event=login_failed').status_code == 200
        attack = '<script>alert(1)</script>'
        r = client.get('/admin/logs', query_string={'event': attack})
        assert attack not in r.text and '&lt;script&gt;' in r.text
    runner = app.test_cli_runner()
    assert runner.invoke(args=['set-role', 'user@example.com', 'user']).exit_code == 0
    with app.app_context():
        rows = db.session.execute(db.select(AuditEvent)).scalars().all()
        names = {row.event for row in rows}
        assert {'register_success', 'login_failed', 'login_success', 'logout',
                'admin_access_denied', 'admin_access_granted', 'mfa_required',
                'mfa_failed', 'mfa_success', 'role_set_user'} <= names
        serialized = repr([{col.name: getattr(row, col.name) for col in AuditEvent.__table__.columns}
                           for row in rows])
        for private in [password, bad_password, password_hash, secret, encrypted,
                        app.config['SECRET_KEY'], app.config['TOTP_ENCRYPTION_KEY']]:
            assert private not in serialized
        assert 'admin@example.com' not in serialized
        cli_event = next(row for row in rows if row.event == 'role_set_user')
        assert cli_event.source == 'local-cli' and cli_event.status is None
    assert logout().status_code == 302
    assert client.post('/login', data={'password': bad_password}).status_code == 400
    limiter.reset()
    for _ in range(5):
        assert post('/login', {**credentials, 'password': bad_password}).status_code == 401
    assert post('/login', credentials).status_code == 429
    with app.app_context():
        names = set(db.session.execute(db.select(AuditEvent.event)).scalars())
        assert {'request_rejected', 'rate_limit_exceeded'} <= names
