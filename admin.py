"""Server-side authorization for all routes in the admin blueprint."""
import click
from flask import Blueprint, abort, render_template, session, request
from flask_login import current_user


def install_admin(app, db, User, login_manager, AuditEvent, audit_event, campus):
    admin = Blueprint('admin', __name__, url_prefix='/admin')

    @admin.before_request
    def require_admin():
        # User is reloaded from the database each request. Never trust a role
        # supplied by a form, URL, or copied into a browser session.
        if not current_user.is_authenticated:
            audit_event('admin_access_denied')
            return login_manager.unauthorized()
        if current_user.role != 'admin':
            audit_event('admin_access_denied', current_user.id)
            abort(403)
        # Also reject old password-only sessions after promotion/enrollment.
        if not current_user.mfa_enabled or session.get('mfa_verified_user') != current_user.id:
            audit_event('admin_access_denied', current_user.id)
            abort(403)

        audit_event('admin_access_granted', current_user.id)

    @admin.get('')
    @admin.get('/')
    def index():
        users = db.paginate(
            db.select(User).order_by(User.id), per_page=25, max_per_page=25,
            error_out=False,
        )
        return render_template('admin.html', users=users)

    @admin.get('/logs')
    def logs():
        event_filter = request.args.get('event', '').strip()[:50]
        query = db.select(AuditEvent)
        if event_filter:
            query = query.where(AuditEvent.event == event_filter)
        events = db.paginate(query.order_by(AuditEvent.id.desc()),
                             per_page=30, max_per_page=30, error_out=False)
        return render_template('audit_logs.html', events=events, event_filter=event_filter)

    admin.add_url_rule('/courses', 'manage_courses', campus['admin_courses'], methods=['GET', 'POST'])
    admin.add_url_rule('/announcements', 'manage_announcements', campus['admin_announcements'], methods=['GET', 'POST'])
    app.register_blueprint(admin)

    @app.errorhandler(403)
    def forbidden(error):
        return render_template('403.html'), 403

    @app.cli.command('set-role')
    @click.argument('email')
    @click.argument('role', type=click.Choice(['user', 'admin']))
    def set_role(email, role):
        """Local operator command: set-role EMAIL user|admin."""
        user = db.session.execute(db.select(User).where(
            User.email == email.strip().lower())).scalar_one_or_none()
        if user is None:
            raise click.ClickException('Account not found. Register it first.')
        if role == 'admin' and not user.mfa_enabled:
            raise click.ClickException('Enable MFA on this account before granting admin access.')
        user.role = role
        db.session.commit()
        audit_event('role_set_' + role, user.id)
        click.echo(f'Role updated: {user.email} -> {role}')
