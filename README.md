# Secure Authentication System — audit logging checkpoint

Local Flask learning project: registration, scrypt password hashing, sessions,
TOTP MFA, single-use recovery codes, server-side RBAC, and admin audit logs.

## Update an existing Windows project

1. Stop the server (Ctrl+C) and back up the project folder.
2. Copy app.py, mfa.py, admin.py, audit.py, requirements.txt, all templates and
   all four test_*.py files into the matching locations of your existing project.
3. Keep your existing .env, .venv and instance/auth.db. Do not regenerate either
   key, re-enroll MFA, reset roles, or delete the database.
4. In the project folder with the virtual environment activated, run:

```powershell
python -m pip install -r requirements.txt
python -m flask --app app init-db
python app.py
```

init-db creates missing tables, including audit_events, and preserves existing
accounts, roles, MFA secrets and recovery codes. It is not a schema migration tool.
Always run from your original project, not a separate extracted folder.

## View and generate audit events

Log in as your existing admin using password plus TOTP or a recovery code.
Open admin dashboard -> View security audit logs, or /admin/logs directly.
Logs are newest first, 30 per page, and filterable by exact event name.

To test: use Incognito to submit a wrong password, then log in as a normal
user and visit /admin. Refresh the admin's log page. Expect login_failed and
admin_access_denied. Check ordinary users get 403 on /admin/logs as well.
Passwords, OTPs, recovery code values and session cookies must never be shared.

### Events

- register_success, register_rejected (duplicate account)
- login_failed (invalid credentials), login_success (full login completed)
- mfa_required (password accepted; NOT a full successful login)
- mfa_failed, mfa_success, mfa_enabled, mfa_setup_password_failed
- recovery_login_success, recovery_codes_generated, recovery_generation_failed
- logout
- admin_access_denied, admin_access_granted (including viewing logs)
- role_set_admin, role_set_user (trusted local operator command)
- rate_limit_exceeded (HTTP 429), request_rejected (HTTP 400, including CSRF)

Each record contains a UTC timestamp, event name, user ID when known, direct
peer IP, Flask endpoint name, and actual HTTP response status. User ID is a target
account ID for login attempts and CLI role changes, not proof of who attempted
an action. Unrecognized accounts are recorded with no user ID. For local CLI
changes source is local-cli and HTTP status is absent. No individual operator
identity is collected. Password verification failures have HTTP 401; a rejected
MFA form may still return an HTML page with HTTP 200, so use event type to interpret
outcome. Logs only capture events after this update; past events are not rebuilt.

UTC is 5 hours 30 minutes behind Sri Lanka time. Local requests normally show
127.0.0.1. Forwarded-IP headers are deliberately not trusted. If deploying behind
a proxy, configure trusted proxy handling explicitly rather than accepting a
client-supplied IP. Viewing the log page is logged after its response, so that
view event becomes visible on the next refresh.

## Security and logging limits

The log writer uses an allow-listed schema and never accepts request bodies,
email input, query strings, headers, passwords, OTPs, recovery codes, encryption
keys, raw sessions or exception details. Templates autoescape displayed values.
The admin blueprint applies the same role/MFA guard to the user list and logs.
A log transaction is independent of the business transaction. Audit writes are
best-effort: if storage fails, a generic server error message is logged and the
original response is preserved. This means an action can succeed without an
audit row during a logging outage. This checkpoint is not a compliance audit
system. SQLite logs are not tamper-evident; someone with database access can
modify them. There is no retention/rotation, export, alert engine or SIEM feed yet.
Invalid-format forms and challenge-expiry redirects are not individually logged
unless they produce one of the HTTP events above.

## Role management

Register and enable MFA on an account before making it admin:

```powershell
python -m flask --app app set-role "YOUR_REGISTERED_EMAIL" admin
```

Then log out and log in with MFA. The command only runs on the trusted local
server. Public registration always assigns user. To demote:

```powershell
python -m flask --app app set-role "YOUR_REGISTERED_EMAIL" user
```

Normal users receive 403 on /admin and /admin/logs. Guests are redirected to
login. Admin sessions must carry completed MFA evidence. Demotion is effective
on the next request. Admin pages are read-only and never display stored secrets.

## Recovery codes

Dashboard -> Generate recovery codes. Confirm your password and a NEW TOTP
(not the one just used to log in). Save all eight codes offline or in a password
manager. Each code contains 128 random bits and is stored only as a SHA-256 hash.
On the MFA login screen leave the TOTP field empty to use one recovery code.
Code consumption and challenge deletion are atomic. Regeneration invalidates
all previous codes and requires a fresh TOTP. Lost-phone re-enrollment/reset is
not implemented yet; keep your authenticator entry.

## Tests

```powershell
python -m pip install pytest
python -m pytest -q test_mfa.py test_recovery.py test_rbac.py test_audit.py
```

Expected: 4 passed. Tests isolate their data in an in-memory SQLite database and
never modify your instance/auth.db. Tests cover TOTP/recovery replay, CSRF,
challenge expiry, role checks and demotion, audit coverage, secret exclusion,
log access protection, escaped filter input and rate-limit logging.

## Fresh setup only

Create/activate a venv, install requirements and copy .env.example to .env.
Generate SECRET_KEY with secrets.token_hex(32), and TOTP_ENCRYPTION_KEY with
Fernet.generate_key().decode(). Replace the placeholders; do not use example
values. Run init-db and app.py, then register at /register. Keep keys safe.

## Remaining deployment limits

This is a local learning app, bound to 127.0.0.1, not a production service.
HTTPS and Secure cookies, shared durable rate limiting, session revocation,
email verification, password reset, retention and operational monitoring remain.
Signed browser cookies are not encrypted. Logout clears the browser session
but does not centrally revoke a previously copied cookie. Memory rate limits
reset on restart and do not coordinate multiple workers. Never commit .env,
instance/, actual codes, QR secrets, or databases to GitHub. Logs also contain
security metadata; do not publish a real database or personal log screenshots.
