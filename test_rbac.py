"""Authorization checks: roles, MFA, and direct URL access."""
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
from app import app, db, User, limiter


def test_rbac_security():
    app.config['TESTING'] = True
    password = 'Unique RBAC test passphrase 392!'
    secret = pyotp.random_base32()
    cipher = Fernet(app.config['TOTP_ENCRYPTION_KEY'])
    with app.app_context():
        db.drop_all()
        db.create_all()
        db.session.add(User(email='admin@example.com', password_hash=generate_password_hash(password),
            role='user', mfa_enabled=True, totp_secret_encrypted=cipher.encrypt(secret.encode()).decode()))
        db.session.commit()
    limiter.reset()
    client = app.test_client()
    def token(path):
        r = client.get(path)
        assert r.status_code == 200
        return re.search(r'name="csrf_token"[^>]*value="([^"]+)"', r.text).group(1)
    def post(path, data):
        return client.post(path, data={**data, 'csrf_token': token(path)})
    runner = app.test_cli_runner()
    assert client.get('/admin').status_code == 302
    assert client.get('/admin/').status_code == 302
    credentials = {'email': 'user@example.com', 'password': password}
    assert post('/register', {**credentials, 'confirm_password': password, 'role': 'admin'}).status_code == 302
    with app.app_context():
        user = db.session.execute(db.select(User).where(User.email == credentials['email'])).scalar_one()
        assert user.role == 'user'
    assert post('/login', credentials).status_code == 302
    assert client.get('/dashboard').status_code == 200
    assert client.get('/admin').status_code == 403
    assert client.get('/admin/?role=admin').status_code == 403
    with client.session_transaction() as sess:
        sess['role'] = 'admin'
    assert client.get('/admin').status_code == 403
    assert runner.invoke(args=['set-role', 'user@example.com', 'admin']).exit_code != 0
    assert runner.invoke(args=['set-role', 'missing@example.com', 'admin']).exit_code != 0
    assert runner.invoke(args=['set-role', 'user@example.com', 'owner']).exit_code != 0
    assert runner.invoke(args=['set-role', 'admin@example.com', 'admin']).exit_code == 0
    assert client.post('/logout', data={'csrf_token': token('/dashboard')}).status_code == 302
    with patch('mfa.time', SimpleNamespace(time=lambda: 1800000000)):
        assert post('/login', {'email': 'admin@example.com', 'password': password}).location.endswith('/mfa/verify')
        assert client.get('/admin').status_code == 302
        assert post('/mfa/verify', {'code': pyotp.TOTP(secret).at(1800000000)}).location.endswith('/dashboard')
        r = client.get('/admin')
        assert r.status_code == 200 and 'user@example.com' in r.text
        assert client.get('/admin/').status_code == 200
        with app.app_context():
            admin = db.session.execute(db.select(User).where(User.email == 'admin@example.com')).scalar_one()
            assert admin.password_hash not in r.text and admin.totp_secret_encrypted not in r.text
        # Role demotion takes effect on the next request, even in an existing session.
        assert runner.invoke(args=['set-role', 'admin@example.com', 'user']).exit_code == 0
        assert client.get('/admin').status_code == 403
        assert runner.invoke(args=['set-role', 'admin@example.com', 'admin']).exit_code == 0
        # An old authenticated session without an MFA-completed marker is rejected.
        with client.session_transaction() as sess:
            sess.pop('mfa_verified_user', None)
        assert client.get('/admin').status_code == 403
