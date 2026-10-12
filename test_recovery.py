"""Recovery security checks with an isolated database and CSRF enabled."""
import os
import re
import secrets
from types import SimpleNamespace
from unittest.mock import patch

import pyotp
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

os.environ.setdefault('SECRET_KEY', secrets.token_hex(32))
os.environ.setdefault('TOTP_ENCRYPTION_KEY', Fernet.generate_key().decode())
os.environ['AUTH_DATABASE_URI'] = 'sqlite://'
from app import app, db, User, limiter


def test_recovery_security():
    app.config['TESTING'] = True
    cipher = Fernet(app.config['TOTP_ENCRYPTION_KEY'])
    secret = pyotp.random_base32()
    password = 'Unique recovery test password!'
    credentials = {'email': 'recovery@example.com', 'password': password}
    with app.app_context():
        db.drop_all()
        db.create_all()
        db.session.add(User(email=credentials['email'], password_hash=generate_password_hash(password),
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
    def logout():
        assert client.post('/logout', data={'csrf_token': token('/dashboard')}).status_code == 302
    assert client.get('/mfa/recovery').status_code == 302
    with patch('mfa.time', SimpleNamespace(time=lambda: 1800000000)):
        assert post('/login', credentials).location.endswith('/mfa/verify')
        assert client.get('/mfa/recovery').status_code == 302
        assert post('/mfa/verify', {'code': pyotp.TOTP(secret).at(1800000000)}).status_code == 302
        assert post('/mfa/recovery', {'password': password, 'code': pyotp.TOTP(secret).at(1800000000)}).status_code == 400
    with patch('mfa.time', SimpleNamespace(time=lambda: 1800000030)):
        data = {'password': password, 'code': pyotp.TOTP(secret).at(1800000030)}
        assert client.post('/mfa/recovery', data=data).status_code == 400
        assert post('/mfa/recovery', {**data, 'password': 'wrong'}).status_code == 401
        response = post('/mfa/recovery', data)
        codes = re.findall(r'(?:[A-F0-9]{4}-){7}[A-F0-9]{4}', response.text)
        assert len(codes) == 8 and len(set(codes)) == 8
        assert response.headers['Cache-Control'] == 'no-store'
        assert codes[0] not in client.get('/mfa/recovery').text
        with app.app_context():
            hashes = db.session.execute(text('select code_hash from recovery_codes')).scalars().all()
            assert len(hashes) == 8 and all(len(h) == 64 for h in hashes)
            assert all(code not in str(hashes) for code in codes)
        logout()
        # A recovery code alone cannot start an authenticated session.
        assert client.get('/mfa/verify').location.endswith('/login')
        assert post('/login', credentials).location.endswith('/mfa/verify')
        assert post('/mfa/verify', {'recovery_code': codes[0]}).location.endswith('/dashboard')
        logout()
        assert post('/login', credentials).status_code == 302
        assert 'Invalid' in post('/mfa/verify', {'recovery_code': codes[0]}).text
        assert client.get('/dashboard').status_code == 302
        assert post('/mfa/verify', {'recovery_code': codes[1]}).status_code == 302
    with patch('mfa.time', SimpleNamespace(time=lambda: 1800000060)):
        limiter.reset()
        response = post('/mfa/recovery', {'password': password, 'code': pyotp.TOTP(secret).at(1800000060)})
        new_codes = re.findall(r'(?:[A-F0-9]{4}-){7}[A-F0-9]{4}', response.text)
        assert len(new_codes) == 8
        logout()
        assert post('/login', credentials).status_code == 302
        assert 'Invalid' in post('/mfa/verify', {'recovery_code': codes[2]}).text
        assert post('/mfa/verify', {'recovery_code': new_codes[0]}).location.endswith('/dashboard')
        with app.app_context():
            assert db.session.execute(text('select count(*) from recovery_codes')).scalar_one() == 7
