import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, session, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect, FlaskForm
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length

load_dotenv(Path(__file__).with_name('.env'))
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ['SECRET_KEY'],
    TOTP_ENCRYPTION_KEY=os.environ['TOTP_ENCRYPTION_KEY'],
    SQLALCHEMY_DATABASE_URI=os.environ.get('AUTH_DATABASE_URI', 'sqlite:///auth.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,  # Local HTTP lab only; enable with HTTPS.
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=20),
    MAX_CONTENT_LENGTH=16 * 1024,
)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
from audit import install_audit
AuditEvent, audit_event = install_audit(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to continue.'
# Development only: counters reset on restart and are not shared by workers.
limiter = Limiter(key_func=get_remote_address, app=app, storage_uri='memory://')
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32), method='scrypt')


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    totp_secret_encrypted = db.Column(db.Text, nullable=True)
    last_totp_step = db.Column(db.BigInteger, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False,
                           default=lambda: datetime.now(timezone.utc))


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


def normalize_email(value):
    return value.strip().lower() if value else value


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=254)],
                        filters=[normalize_email])
    password = PasswordField('Password', validators=[DataRequired(), Length(
        min=15, max=128, message='Use a password between 15 and 128 characters.')])
    confirm_password = PasswordField('Confirm password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Create account')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=254)],
                        filters=[normalize_email])
    password = PasswordField('Password', validators=[DataRequired(), Length(max=128)])
    submit = SubmitField('Log in')


@app.get('/')
def home():
    return redirect(url_for('dashboard' if current_user.is_authenticated else 'login'))


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('5 per minute', methods=['POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    password_hash=generate_password_hash(form.password.data, method='scrypt'),
                    role='user')
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            audit_event('register_rejected')
            form.email.errors.append('Unable to create an account with this email.')
        else:
            audit_event('register_success', user.id)
            flash('Account created successfully! Please log in.')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('5 per minute', methods=['POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.execute(db.select(User).where(
            User.email == form.email.data)).scalar_one_or_none()
        password_ok = check_password_hash(
            user.password_hash if user else DUMMY_PASSWORD_HASH, form.password.data)
        if user is None or not password_ok:
            audit_event('login_failed', user.id if user else None)
            flash('Invalid email or password.')
            return render_template('login.html', form=form), 401
        if user.mfa_enabled:
            audit_event('mfa_required', user.id)
            return begin_mfa_login(user)
        session.clear()
        login_user(user, remember=False)
        session.permanent = True
        audit_event('login_success', user.id)
        return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.get('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', **campus['dashboard_data']())


@app.post('/logout')
@login_required
def logout():
    audit_event('logout', current_user.id)
    logout_user()
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.after_request
def prevent_sensitive_page_caching(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response


@app.cli.command('init-db')
def init_db():
    """Create missing tables without deleting existing accounts."""
    db.create_all()
    click.echo('Database tables created successfully.')


from mfa import install_mfa
begin_mfa_login, MFAChallenge = install_mfa(app, db, User, limiter, audit_event)


from campus import install_campus
campus = install_campus(app, db, User, audit_event)

from admin import install_admin
install_admin(app, db, User, login_manager, AuditEvent, audit_event, campus)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
