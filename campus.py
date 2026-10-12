"""Campus portal features; separate tables preserve existing auth data."""
from datetime import datetime, timezone
import click
from flask import abort, flash, redirect, render_template, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from sqlalchemy.exc import IntegrityError
from wtforms import StringField, TextAreaField, IntegerField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length, NumberRange, Regexp


def install_campus(app, db, User, audit_event):
    class StudentProfile(db.Model):
        __tablename__ = 'student_profiles'
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
        full_name = db.Column(db.String(100), nullable=False)
        programme = db.Column(db.String(100), nullable=False)
        study_year = db.Column(db.Integer, nullable=False)

    class Course(db.Model):
        __tablename__ = 'courses'
        id = db.Column(db.Integer, primary_key=True)
        code = db.Column(db.String(20), unique=True, nullable=False)
        title = db.Column(db.String(120), nullable=False)
        description = db.Column(db.Text, nullable=False)
        credits = db.Column(db.Integer, nullable=False)

    class Enrollment(db.Model):
        __tablename__ = 'enrollments'
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
        course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), primary_key=True)
        created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    class Announcement(db.Model):
        __tablename__ = 'announcements'
        id = db.Column(db.Integer, primary_key=True)
        title = db.Column(db.String(120), nullable=False)
        body = db.Column(db.Text, nullable=False)
        author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
        created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    class ProfileForm(FlaskForm):
        full_name = StringField('Full name', validators=[DataRequired(), Length(max=100)])
        programme = StringField('Programme', validators=[DataRequired(), Length(max=100)])
        study_year = SelectField('Year of study', choices=[(i, f'Year {i}') for i in range(1, 7)], coerce=int)
        submit = SubmitField('Save profile')

    class CourseForm(FlaskForm):
        code = StringField('Course code', validators=[DataRequired(), Length(max=20), Regexp(r'^[A-Za-z0-9-]+$')])
        title = StringField('Course title', validators=[DataRequired(), Length(max=120)])
        description = TextAreaField('Description', validators=[DataRequired(), Length(max=2000)])
        credits = IntegerField('Credits', validators=[DataRequired(), NumberRange(min=1, max=30)])
        submit = SubmitField('Create course')

    class AnnouncementForm(FlaskForm):
        title = StringField('Title', validators=[DataRequired(), Length(max=120)])
        body = TextAreaField('Message', validators=[DataRequired(), Length(max=4000)])
        submit = SubmitField('Publish announcement')

    def dashboard_data():
        courses = db.session.execute(db.select(Course).join(Enrollment, Enrollment.course_id == Course.id)
            .where(Enrollment.user_id == current_user.id).order_by(Course.code)).scalars().all()
        return dict(profile=db.session.get(StudentProfile, current_user.id), courses=courses,
            credits=sum(c.credits for c in courses),
            notices=db.session.execute(db.select(Announcement).order_by(Announcement.id.desc()).limit(3)).scalars().all())

    @app.route('/profile', methods=['GET', 'POST'])
    @login_required
    def student_profile():
        profile = db.session.get(StudentProfile, current_user.id)
        form = ProfileForm(obj=profile)
        if form.validate_on_submit():
            if profile is None:
                profile = StudentProfile(user_id=current_user.id)
                db.session.add(profile)
            profile.full_name = form.full_name.data.strip()
            profile.programme = form.programme.data.strip()
            profile.study_year = form.study_year.data
            db.session.commit()
            audit_event('profile_updated', current_user.id)
            flash('Your profile has been saved.')
            return redirect(url_for('student_profile'))
        return render_template('profile.html', form=form)

    @app.get('/courses')
    @login_required
    def courses():
        catalog = db.paginate(db.select(Course).order_by(Course.code), per_page=12, max_per_page=12, error_out=False)
        enrolled = set(db.session.execute(db.select(Enrollment.course_id).where(Enrollment.user_id == current_user.id)).scalars())
        return render_template('courses.html', catalog=catalog, enrolled=enrolled)

    @app.post('/courses/<int:course_id>/enroll')
    @login_required
    def enroll(course_id):
        db.get_or_404(Course, course_id)
        # Account ID always comes from authenticated identity, never a submitted form.
        if db.session.get(Enrollment, (current_user.id, course_id)) is None:
            db.session.add(Enrollment(user_id=current_user.id, course_id=course_id))
            try:
                db.session.commit()
                audit_event('course_enrolled', current_user.id)
            except IntegrityError:
                db.session.rollback()
        flash('Course is in your enrolled courses.')
        return redirect(url_for('courses'))

    @app.post('/courses/<int:course_id>/drop')
    @login_required
    def drop_course(course_id):
        enrollment = db.session.get(Enrollment, (current_user.id, course_id))
        if enrollment is None:
            abort(404)
        db.session.delete(enrollment)
        db.session.commit()
        audit_event('course_dropped', current_user.id)
        flash('Course removed from your enrollments.')
        return redirect(url_for('courses'))

    @app.get('/announcements')
    @login_required
    def announcements():
        notices = db.paginate(db.select(Announcement).order_by(Announcement.id.desc()), per_page=10, max_per_page=10, error_out=False)
        return render_template('announcements.html', notices=notices)

    @app.get('/security')
    @login_required
    def security():
        return render_template('security.html')

    # These functions are attached to the existing guarded admin blueprint BEFORE registration.
    def admin_courses():
        form = CourseForm()
        if form.validate_on_submit():
            course = Course(code=form.code.data.upper(), title=form.title.data.strip(),
                            description=form.description.data.strip(), credits=form.credits.data)
            db.session.add(course)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                form.code.errors.append('This course code already exists.')
            else:
                audit_event('course_created', current_user.id)
                flash('Course created. Students can now enroll.')
                return redirect(url_for('admin.manage_courses'))
        return render_template('manage.html', title='Create a course', subtitle='Add a module to the student course catalog.', form=form)

    def admin_announcements():
        form = AnnouncementForm()
        if form.validate_on_submit():
            db.session.add(Announcement(title=form.title.data.strip(), body=form.body.data.strip(), author_id=current_user.id))
            db.session.commit()
            audit_event('announcement_published', current_user.id)
            flash('Announcement published to the student portal.')
            return redirect(url_for('announcements'))
        return render_template('manage.html', title='Publish an announcement', subtitle='Share a campus update with all signed-in users.', form=form)

    @app.cli.command('seed-campus')
    def seed_campus():
        """Add clearly labeled demonstration content; no accounts or enrollments."""
        samples = [('DEMO-CS101', 'Introduction to Computing', 'Build a foundation in computing concepts and problem solving.', 3),
                   ('DEMO-NET201', 'Computer Networks', 'Explore addressing, routing and the protocols that connect systems.', 3),
                   ('DEMO-SEC301', 'Cybersecurity Fundamentals', 'Study security principles, authentication and access control.', 4),
                   ('DEMO-PY101', 'Python Programming', 'Practice Python through structured programming exercises.', 3)]
        for code, title, description, credits in samples:
            if db.session.execute(db.select(Course).where(Course.code == code)).scalar_one_or_none() is None:
                db.session.add(Course(code=code, title=title, description=description, credits=credits))
        title = 'Demo: Welcome to CampusConnect'
        if db.session.execute(db.select(Announcement).where(Announcement.title == title)).scalar_one_or_none() is None:
            db.session.add(Announcement(title=title, body='This is a demonstration campus portal. Complete your profile, browse the demo courses, and secure your account with MFA. Course enrollment here is for this local project only.'))
        db.session.commit()
        click.echo('Demo courses and announcement added. Existing accounts and enrollments preserved.')

    return {'dashboard_data': dashboard_data, 'admin_courses': admin_courses,
            'admin_announcements': admin_announcements,
            'models': (StudentProfile, Course, Enrollment, Announcement)}
