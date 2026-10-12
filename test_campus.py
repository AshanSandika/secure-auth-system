"""Campus feature access, ownership, persistence, and duplicate-enrollment tests."""
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
from app import app, db, User, limiter, campus


def test_campus_flow():
    app.config['TESTING'] = True
    Profile, Course, Enrollment, Announcement = campus['models']
    secret = pyotp.random_base32()
    password = 'A campus test passphrase 824!'
    cipher = Fernet(app.config['TOTP_ENCRYPTION_KEY'])
    with app.app_context():
        db.drop_all(); db.create_all()
        db.session.add_all([
            User(id=1, email='student@example.com', password_hash=generate_password_hash(password), role='user'),
            User(id=2, email='other@example.com', password_hash=generate_password_hash(password), role='user'),
            User(id=3, email='admin@example.com', password_hash=generate_password_hash(password), role='admin',
                 mfa_enabled=True, totp_secret_encrypted=cipher.encrypt(secret.encode()).decode())])
        db.session.commit()
    limiter.reset()
    runner = app.test_cli_runner()
    assert runner.invoke(args=['seed-campus']).exit_code == 0
    assert runner.invoke(args=['seed-campus']).exit_code == 0
    with app.app_context():
        assert db.session.execute(db.select(db.func.count()).select_from(Course)).scalar_one() == 4
    client = app.test_client()
    def token(path):
        response = client.get(path)
        assert response.status_code == 200, response.text[:300]
        return re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.text).group(1)
    def post(path, data, token_path=None):
        return client.post(path, data={**data, 'csrf_token': token(token_path or path)})
    def logout():
        assert client.post('/logout', data={'csrf_token': token('/dashboard')}).status_code == 302
    for path in ['/dashboard','/profile','/courses','/announcements','/security','/admin/courses','/admin/announcements']:
        assert client.get(path).status_code == 302
    assert post('/login', {'email':'student@example.com','password':password}).status_code == 302
    assert post('/profile', {'full_name':'Demo Student','programme':'Cybersecurity','study_year':'3','user_id':'2'}).status_code == 302
    with app.app_context():
        assert db.session.get(Profile, 1).full_name == 'Demo Student'
        assert db.session.get(Profile, 2) is None
    assert client.get('/courses').status_code == 200
    assert client.post('/courses/1/enroll').status_code == 400
    assert post('/courses/1/enroll', {'user_id':2}, '/courses').status_code == 302
    assert post('/courses/1/enroll', {}, '/courses').status_code == 302
    with app.app_context():
        assert db.session.get(Enrollment, (1,1)) is not None
        assert db.session.get(Enrollment, (2,1)) is None
        assert db.session.execute(db.select(db.func.count()).select_from(Enrollment)).scalar_one() == 1
    assert 'Demo Student' in client.get('/dashboard').text
    for path in ['/admin/courses','/admin/announcements']:
        assert client.get(path).status_code == 403
        assert post(path, {'title':'Unauthorized'}, '/profile').status_code == 403
    logout()
    assert post('/login', {'email':'other@example.com','password':password}).status_code == 302
    assert post('/courses/1/drop', {'user_id':1}, '/courses').status_code == 404
    logout()
    with patch('mfa.time', SimpleNamespace(time=lambda: 1800000000)):
        assert post('/login', {'email':'admin@example.com','password':password}).location.endswith('/mfa/verify')
        assert client.get('/admin/courses').status_code == 302
        assert post('/mfa/verify', {'code':pyotp.TOTP(secret).at(1800000000)}).status_code == 302
    assert post('/admin/courses', {'code':'CS401','title':'Secure Systems','description':'Build and review security controls.','credits':'4'}).status_code == 302
    assert post('/admin/announcements', {'title':'Campus update','body':'<script>alert(1)</script>'}).status_code == 302
    result = client.get('/announcements')
    assert '<script>alert(1)</script>' not in result.text and '&lt;script&gt;' in result.text
    with app.app_context():
        assert db.session.execute(db.select(Course).where(Course.code=='CS401')).scalar_one().credits == 4
    assert client.get('/admin/logs').status_code == 200
