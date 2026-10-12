"""TOTP enrollment and second-factor login for the local lab."""
import base64
import hashlib
import io
import secrets
import time

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from flask import flash, redirect, render_template, session, url_for
from flask_login import current_user, login_required, login_user
from flask_wtf import FlaskForm
from sqlalchemy import delete, or_, update
from werkzeug.security import check_password_hash
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, Optional


def install_mfa(app, db, User, limiter, audit_event):
    cipher = Fernet(app.config['TOTP_ENCRYPTION_KEY'])

    class MFAChallenge(db.Model):
        __tablename__ = 'mfa_challenges'
        id = db.Column(db.String(64), primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        purpose = db.Column(db.String(16), nullable=False)
        secret_encrypted = db.Column(db.Text, nullable=True)
        expires_at = db.Column(db.BigInteger, nullable=False)
        attempts = db.Column(db.Integer, nullable=False, default=0)

    class RecoveryCode(db.Model):
        __tablename__ = 'recovery_codes'
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
        code_hash = db.Column(db.String(64), nullable=False, unique=True)

    class RecoveryGenerationForm(FlaskForm):
        password = PasswordField('Confirm your password', validators=[DataRequired(), Length(max=128)])
        code = StringField('Current authenticator code', validators=[
            DataRequired(), Regexp(r'^[0-9]{6}$', message='Enter exactly 6 digits.')])
        submit = SubmitField('Generate 8 new recovery codes')

    class LoginMFAForm(FlaskForm):
        code = StringField('Authenticator code', validators=[Optional(), Regexp(r'^[0-9]{6}$')])
        recovery_code = PasswordField('Recovery code', validators=[Optional(), Length(max=64)])
        submit = SubmitField('Verify and log in')

        def validate(self, extra_validators=None):
            if not super().validate(extra_validators):
                return False
            if bool(self.code.data) == bool(self.recovery_code.data):
                self.code.errors.append('Enter either an authenticator code OR a recovery code.')
                return False
            return True

    def recovery_hash(value):
        # 128 random bits per code: fast hashing is appropriate for these random
        # secrets, not for human passwords (which still use scrypt).
        normalized = value.strip().replace('-', '').upper()
        return hashlib.sha256(normalized.encode()).hexdigest()

    class PasswordForm(FlaskForm):
        password = PasswordField('Confirm your password', validators=[DataRequired(), Length(max=128)])
        submit = SubmitField('Create setup QR code')

    class OTPForm(FlaskForm):
        code = StringField('6-digit authenticator code', validators=[
            DataRequired(), Regexp(r'^[0-9]{6}$', message='Enter exactly 6 digits.')])
        submit = SubmitField('Verify code')

    def create_challenge(user, purpose, secret=None):
        db.session.execute(delete(MFAChallenge).where(MFAChallenge.expires_at <= int(time.time())))
        challenge = MFAChallenge(id=secrets.token_urlsafe(32), user_id=user.id,
            purpose=purpose, secret_encrypted=secret, expires_at=int(time.time()) + 300)
        db.session.add(challenge)
        db.session.commit()
        session['mfa_challenge'] = challenge.id

    def begin_login(user):
        session.clear()
        create_challenge(user, 'login')
        return redirect(url_for('mfa_verify'))

    def get_challenge(purpose):
        key = session.get('mfa_challenge')
        ch = db.session.get(MFAChallenge, key) if isinstance(key, str) else None
        if not ch or ch.purpose != purpose or ch.expires_at <= int(time.time()) or ch.attempts >= 5:
            session.pop('mfa_challenge', None)
            return None
        if purpose == 'enroll' and ch.user_id != current_user.id:
            return None
        return ch

    def consume_code(ch, user, code, enrolling=False, recovery=None):
        # Increment in the database, so replaying an older cookie cannot reset attempts.
        changed = db.session.execute(update(MFAChallenge).where(
            MFAChallenge.id == ch.id, MFAChallenge.attempts < 5,
            MFAChallenge.expires_at > int(time.time())
        ).values(attempts=MFAChallenge.attempts + 1)).rowcount
        db.session.commit()
        if changed != 1:
            return False
        if recovery is not None and not enrolling:
            # Delete the matching code and claim the challenge in one transaction.
            # Failed or concurrent attempts roll back both operations.
            consumed = db.session.execute(delete(RecoveryCode).where(
                RecoveryCode.user_id == user.id,
                RecoveryCode.code_hash == recovery_hash(recovery),
                db.select(User.id).where(User.id == user.id, User.mfa_enabled.is_(True)).exists()
            )).rowcount
            removed = db.session.execute(delete(MFAChallenge).where(
                MFAChallenge.id == ch.id, MFAChallenge.expires_at > int(time.time())
            )).rowcount
            if consumed != 1 or removed != 1:
                db.session.rollback()
                return False
            db.session.commit()
            session.pop('mfa_challenge', None)
            return True
        encrypted = ch.secret_encrypted if enrolling else user.totp_secret_encrypted
        try:
            secret = cipher.decrypt(encrypted.encode()).decode()
        except (InvalidToken, AttributeError, UnicodeError):
            return False
        totp = pyotp.TOTP(secret)
        step = int(time.time()) // totp.interval
        # Strict current 30-second step. Keep the PC and phone clocks synchronized.
        if not pyotp.utils.strings_equal(totp.at(step * totp.interval), code):
            return False
        conditions = [User.id == user.id, User.mfa_enabled.is_(not enrolling)]
        values = {'last_totp_step': step}
        if enrolling:
            values.update(mfa_enabled=True, totp_secret_encrypted=encrypted)
        else:
            conditions.extend([User.totp_secret_encrypted == encrypted,
                or_(User.last_totp_step.is_(None), User.last_totp_step < step)])
        # Claim challenge and OTP time step atomically: concurrent reuse cannot succeed.
        removed = db.session.execute(delete(MFAChallenge).where(
            MFAChallenge.id == ch.id, MFAChallenge.expires_at > int(time.time())
        )).rowcount
        updated = db.session.execute(update(User).where(*conditions).values(**values)).rowcount
        if removed != 1 or updated != 1:
            db.session.rollback()
            return False
        db.session.commit()
        session.pop('mfa_challenge', None)
        return True

    @app.route('/mfa/setup', methods=['GET', 'POST'])
    @login_required
    @limiter.limit('5 per minute', methods=['POST'])
    def mfa_setup():
        if current_user.mfa_enabled:
            return redirect(url_for('dashboard'))
        form = PasswordForm()
        if form.validate_on_submit():
            if not check_password_hash(current_user.password_hash, form.password.data):
                audit_event('mfa_setup_password_failed', current_user.id)
                flash('Incorrect password.')
                return render_template('mfa.html', title='Enable MFA', form=form), 401
            secret = cipher.encrypt(pyotp.random_base32().encode()).decode()
            create_challenge(current_user, 'enroll', secret)
            return redirect(url_for('mfa_confirm'))
        return render_template('mfa.html', title='Enable MFA', form=form)

    @app.route('/mfa/confirm', methods=['GET', 'POST'])
    @login_required
    @limiter.limit('5 per minute', methods=['POST'])
    def mfa_confirm():
        if current_user.mfa_enabled:
            return redirect(url_for('dashboard'))
        ch = get_challenge('enroll')
        if ch is None:
            flash('Setup expired or attempt limit reached. Confirm your password again.')
            return redirect(url_for('mfa_setup'))
        form = OTPForm()
        if form.validate_on_submit():
            if consume_code(ch, current_user, form.code.data, enrolling=True):
                audit_event('mfa_enabled', current_user.id)
                # Require a new full login after enrollment; also consumes the setup code.
                from flask_login import logout_user
                logout_user()
                session.clear()
                flash('MFA enabled! Log in again and wait for a NEW authenticator code.')
                return redirect(url_for('login'))
            audit_event('mfa_failed', current_user.id)
            flash('Invalid or already used code. Wait for a new code and try again.')
        try:
            secret = cipher.decrypt(ch.secret_encrypted.encode()).decode()
        except InvalidToken:
            session.pop('mfa_challenge', None)
            flash('Cannot read setup secret. Check the encryption key.')
            return redirect(url_for('mfa_setup'))
        uri = pyotp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name='Secure Auth Lab')
        buffer = io.BytesIO()
        qrcode.make(uri).save(buffer, format='PNG')
        qr = base64.b64encode(buffer.getvalue()).decode()
        return render_template('mfa.html', title='Scan your QR code', form=form, qr=qr)

    @app.route('/mfa/verify', methods=['GET', 'POST'])
    @limiter.limit('5 per minute', methods=['POST'])
    def mfa_verify():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        ch = get_challenge('login')
        if ch is None:
            flash('Verification expired or attempt limit reached. Log in again.')
            return redirect(url_for('login'))
        user = db.session.get(User, ch.user_id)
        if user is None or not user.mfa_enabled:
            session.clear()
            return redirect(url_for('login'))
        form = LoginMFAForm()
        if form.validate_on_submit():
            if consume_code(ch, user, form.code.data, recovery=form.recovery_code.data or None):
                session.clear()
                login_user(user, remember=False)
                session['mfa_verified_user'] = user.id
                audit_event('recovery_login_success' if form.recovery_code.data else 'mfa_success', user.id)
                audit_event('login_success', user.id)
                session.permanent = True
                return redirect(url_for('dashboard'))
            audit_event('mfa_failed', user.id)
            flash('Invalid, expired, or already used code. Try an unused code.')
        return render_template('mfa.html', title='Verify your login', form=form)

    @app.route('/mfa/recovery', methods=['GET', 'POST'])
    @login_required
    @limiter.limit('5 per minute', methods=['POST'])
    def recovery_codes():
        if not current_user.mfa_enabled:
            flash('Enable MFA before generating recovery codes.')
            return redirect(url_for('mfa_setup'))
        form = RecoveryGenerationForm()
        if form.validate_on_submit():
            if not check_password_hash(current_user.password_hash, form.password.data):
                audit_event('recovery_generation_failed', current_user.id)
                flash('Password or authenticator code is incorrect.')
                return render_template('recovery.html', form=form), 401
            encrypted = current_user.totp_secret_encrypted
            try:
                secret = cipher.decrypt(encrypted.encode()).decode()
            except (InvalidToken, AttributeError, UnicodeError):
                flash('Cannot read your MFA secret. Check the encryption key.')
                return render_template('recovery.html', form=form), 400
            step = int(time.time()) // 30
            if not pyotp.utils.strings_equal(pyotp.TOTP(secret).at(step * 30), form.code.data):
                audit_event('recovery_generation_failed', current_user.id)
                flash('Password or authenticator code is incorrect.')
                return render_template('recovery.html', form=form), 401
            claimed = db.session.execute(update(User).where(
                User.id == current_user.id, User.mfa_enabled.is_(True),
                User.totp_secret_encrypted == encrypted,
                or_(User.last_totp_step.is_(None), User.last_totp_step < step)
            ).values(last_totp_step=step)).rowcount
            if claimed != 1:
                db.session.rollback()
                audit_event('recovery_generation_failed', current_user.id)
                flash('This authenticator code was already used. Wait for a new code.')
                return render_template('recovery.html', form=form), 400
            codes = []
            for _ in range(8):
                raw = secrets.token_hex(16).upper()
                codes.append('-'.join(raw[i:i + 4] for i in range(0, len(raw), 4)))
            db.session.execute(delete(RecoveryCode).where(RecoveryCode.user_id == current_user.id))
            db.session.add_all([RecoveryCode(user_id=current_user.id, code_hash=recovery_hash(code))
                               for code in codes])
            db.session.commit()
            audit_event('recovery_codes_generated', current_user.id)
            # Show plaintext only in this response, never in logs, cookies, or DB.
            return render_template('recovery.html', codes=codes)
        return render_template('recovery.html', form=form)

    return begin_login, MFAChallenge
