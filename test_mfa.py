"""Run with: python -m pytest -q test_mfa.py (isolated in-memory database)."""
import os
import re
import secrets
from unittest.mock import patch
from types import SimpleNamespace

import pyotp
from cryptography.fernet import Fernet

os.environ['SECRET_KEY'] = secrets.token_hex(32)
os.environ['TOTP_ENCRYPTION_KEY'] = Fernet.generate_key().decode()
os.environ['AUTH_DATABASE_URI'] = 'sqlite://'
from app import app, db, User, MFAChallenge, limiter


def test_mfa_flow():
    app.config['TESTING'] = True
    client = app.test_client()
    cipher = Fernet(app.config['TOTP_ENCRYPTION_KEY'])
    password = 'A unique test passphrase 723!'
    credentials = {'email': 'test@example.com', 'password': password}
    limiter.reset()
    with app.app_context():
        db.drop_all()
        db.create_all()
    def post(path, data):
        page = client.get(path)
        assert page.status_code == 200, page.location
        token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text).group(1)
        return client.post(path, data={**data, 'csrf_token': token})
    def logout():
        page = client.get('/dashboard')
        token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text).group(1)
        assert client.post('/logout', data={'csrf_token': token}).status_code == 302
    assert post('/register', {**credentials, 'confirm_password': password}).status_code == 302
    assert post('/login', credentials).location.endswith('/dashboard')
    assert client.get('/dashboard').status_code == 200
    assert post('/mfa/setup', {'password': 'incorrect'}).status_code == 401
    assert client.post('/mfa/setup', data={'password': password}).status_code == 400
    assert post('/mfa/setup', {'password': password}).location.endswith('/mfa/confirm')
    assert 'data:image/png;base64,' in client.get('/mfa/confirm').text
    with app.app_context():
        user = db.session.execute(db.select(User)).scalar_one()
        assert not user.mfa_enabled
        ch = db.session.execute(db.select(MFAChallenge)).scalar_one()
        secret = cipher.decrypt(ch.secret_encrypted.encode()).decode()
        assert secret not in ch.secret_encrypted
    with patch('mfa.time', SimpleNamespace(time=lambda: 1800000000)):
        # Extend the test challenge to align with the deterministic test clock.
        with app.app_context():
            ch = db.session.execute(db.select(MFAChallenge)).scalar_one()
            ch.expires_at = 1800000300
            db.session.commit()
        code = pyotp.TOTP(secret).at(1800000000)
        assert post('/mfa/confirm', {'code': code}).location.endswith('/login')
        assert client.get('/dashboard').status_code == 302
        assert post('/login', credentials).location.endswith('/mfa/verify')
        assert client.get('/dashboard').status_code == 302
        assert 'already used' in post('/mfa/verify', {'code': code}).text
        assert client.get('/dashboard').status_code == 302
    with patch('mfa.time', SimpleNamespace(time=lambda: 1800000030)):
        code = pyotp.TOTP(secret).at(1800000030)
        assert post('/mfa/verify', {'code': code}).location.endswith('/dashboard')
        assert client.get('/dashboard').status_code == 200
        logout()
        assert client.get('/dashboard').status_code == 302
        assert post('/login', credentials).location.endswith('/mfa/verify')
        assert 'already used' in post('/mfa/verify', {'code': code}).text
    with patch('mfa.time', SimpleNamespace(time=lambda: 1800000400)):
        assert client.get('/mfa/verify').location.endswith('/login')
    with app.app_context():
        limiter.reset()
    assert post('/login', credentials).location.endswith('/mfa/verify')
    for _ in range(5):
        post('/mfa/verify', {'code': '111111'})
    assert client.get('/mfa/verify').location.endswith('/login')
    print('MFA enrollment, encrypted secret, CSRF, pending-session protection, replay rejection, expiry, attempt cap and logout passed.')
