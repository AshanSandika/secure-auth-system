# Upgrade your existing project to CampusConnect

1. Stop Flask with Ctrl+C. Back up your existing project folder.
2. From this ZIP's campus-connect folder copy the following into your EXISTING
   secure-auth-system folder (the folder containing your .git and .env):
   - app.py, mfa.py, admin.py, audit.py, campus.py
   - requirements.txt, README.md, UPDATE_STEPS.md
   - templates/ (replace matching files and add the new ones)
   - static/ (new folder containing portal.css)
   - all five test_*.py files
3. Keep your existing .git, .env, .venv and instance/auth.db. Do not generate
   new keys, delete the database or run git init again. Do not rename the repo.
4. In the activated virtual environment run:

```powershell
python -m pip install -r requirements.txt
python -m flask --app app init-db
python -m flask --app app seed-campus
python app.py
```

init-db adds student_profiles, courses, enrollments and announcements without
altering your existing users table. seed-campus adds four DEMO courses and a
clearly labeled demo announcement. It creates no accounts or enrollments and
is safe to rerun. You can skip seed-campus to start with an empty catalog.

5. Open http://127.0.0.1:5000/login. Use your EXISTING account and MFA.
   If old styling remains, press Ctrl+F5. Your Authenticator may still show
   Secure Auth Lab; that existing entry continues to work.
6. My profile -> save name, programme and year. Courses -> Enroll now -> Overview.
   Students can only enroll/drop for their own logged-in account.
7. Admin users: Courses -> Create course; Announcements -> Publish update.
   Existing admin directory and audit logs remain available in the sidebar.
8. Account security holds Enable MFA and Generate recovery codes links.

## Verify

```powershell
python -m pip install pytest
python -m pytest -q
```

Expected: 5 passed. Tests use an isolated memory database. Manual checks:
- Old account can sign in with its existing MFA and recovery codes.
- Profile changes appear on Overview.
- Enroll adds a course once; Drop removes only your own enrollment.
- Admin can create courses and publish announcements.
- Students get 403 on /admin, /admin/courses, /admin/announcements and /admin/logs.
- Sign-in and security errors still appear clearly.

## Save the update to your EXISTING GitHub repository

After testing:

```powershell
git status
git add app.py mfa.py admin.py audit.py campus.py
git add templates static requirements.txt README.md UPDATE_STEPS.md
git add test_mfa.py test_recovery.py test_rbac.py test_audit.py test_campus.py
git diff --cached --name-only
git commit -m "Build CampusConnect student portal"
git push
```

Do not stage .env, .venv, instance/, databases or actual recovery codes. The
repository is already initialized and connected: no git init/remote add needed.
