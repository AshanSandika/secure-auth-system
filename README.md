# CampusConnect — secure campus portal

A Flask + SQLite student portal built on a secure authentication learning
project. A navy, white and light-grey interface brings course enrollment,
student profiles and announcements together with MFA and admin access control.
CampusConnect is a fictional demonstration, not an official campus system.

## Features

- Email/password registration and login; scrypt salted password hashes.
- TOTP enrollment with encrypted secrets and one-time code replay prevention.
- Eight single-use recovery codes, stored only as hashes.
- Admin-only user directory, audit logs, course creation and announcements.
- Student profile: name, self-reported programme and study year.
- Portal identifier generated from the user ID (not an official student number).
- Course catalog with own-account enroll/drop and duplicate prevention.
- Overview showing actual enrolled modules/credits and latest announcements.
- Responsive navigation, shared templates and one CSS stylesheet; no CDN assets.
- CSRF-protected mutations, rate-limited authentication, session cookie controls.

## Upgrade from the previous authentication project

Follow UPDATE_STEPS.md. Preserve your .env, .git and instance/auth.db.
All campus tables are new; the existing authentication tables are unchanged.
Run init-db before starting. Existing accounts, MFA, recovery codes, roles and
audit history are retained. The original Authenticator label remains valid.

## Fresh local setup (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Copy .env.example to .env and replace its placeholders with generated keys:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

The first value is SECRET_KEY; the second is TOTP_ENCRYPTION_KEY. Keep these
keys private and stable. Then:

```powershell
python -m flask --app app init-db
python -m flask --app app seed-campus
python app.py
```

Visit http://127.0.0.1:5000/register. Complete My profile after sign-in.
The optional seed-campus command adds four DEMO courses and one labeled demo
announcement. It never creates user accounts or enrolls students.

## Admin access

Register an account, enable MFA under Account security, and use the trusted
local operator command:

```powershell
python -m flask --app app set-role "YOUR_REGISTERED_EMAIL" admin
```

Log out and sign in again with password + TOTP or recovery code. The admin
blueprint requires both the current database role and completed MFA evidence.
Use /admin for users, /admin/logs for audit, /admin/courses to create a course,
and /admin/announcements to publish an announcement. Public registration always
assigns user (displayed as Student). To demote, replace admin with user in the
command; the change takes effect on the next request.

## Project structure

| Path | Purpose |
| --- | --- |
| app.py | Application configuration, auth model and core routes |
| mfa.py | TOTP challenges, encryption and recovery codes |
| admin.py | Central admin guard, user directory and operator commands |
| audit.py | Allow-listed security event storage |
| campus.py | Profiles, courses, enrollments and announcements |
| templates/ | Shared layout and Jinja page templates |
| static/portal.css | Responsive campus theme |
| test_*.py | Five end-to-end security/feature scenarios |
| instance/auth.db | Local SQLite data, excluded from Git |

## Validation

```powershell
python -m pip install pytest
python -m pytest -q
```

Five scenario tests cover authentication, MFA, recovery, RBAC, audit and campus
flows using an isolated in-memory database. Coverage includes CSRF, wrong
passwords, replay, challenge expiry, one-time recovery, role demotion, log
access, secret exclusion, student ownership, duplicate enrollments, admin-only
publishing, and escaped announcement content. Existing data is not modified.

## Data and security behavior

Profiles bind to authenticated user IDs; no user-supplied ID can target another
profile/enrollment. Enrolled credits are computed from selected courses, not
awarded credits or grades. Course capacity, prerequisites and enrollment dates
are not enforced in this demo. Admin-created announcements are plain text and
escaped when rendered. Programmes and years are self-reported, not verified
academic records. Portal IDs are labeled demo identifiers. No grades, fees,
attendance, assignments or timetable are fabricated or implemented.

Audit events include auth and admin actions plus profile_updated,
course_enrolled, course_dropped, course_created and announcement_published.
Logs record UTC time, event, user ID when known, direct peer IP, endpoint and
HTTP status. They do not store passwords, raw codes, cookies, keys or form
bodies. Audit writes are best-effort and stored in a separate transaction;
a logging outage can leave gaps and produces a generic server error message.
Logs are not tamper-evident and have no retention/rotation yet. They contain
security metadata and must not be published as real user data.

## Limitations

This remains a local learning application, not a production campus service.
Use HTTPS with Secure cookies and shared persistent rate limiting before any
real deployment. The Flask development server binds to localhost. Local HTTP
uses SESSION_COOKIE_SECURE=False. Signed sessions are not encrypted. Logout
clears the current browser session but does not revoke a copied cookie. Central
session revocation, email ownership verification, password reset, lost-phone
MFA reset and account deactivation are not implemented. Recovery-code login
works, but new recovery sets require a working authenticator. Retain that entry.
Memory rate counters reset with the server and are not shared across workers.
A real campus needs authoritative student enrollment, institutional SSO,
operational monitoring, policies and review beyond this project.

Keep .env, .venv, instance/, database backups, actual QR codes and recovery
codes out of Git. No passwords, keys or user database are included in this ZIP.
