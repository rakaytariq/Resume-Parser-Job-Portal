import os
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from resume_parser import process_resume
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, FileField
from wtforms.validators import DataRequired, Email
from flask import send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from wtforms import PasswordField
from wtforms.validators import Length, EqualTo





app = Flask(__name__)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# Configure Flask app & database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///jobs.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Job Model
class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    skills = db.Column(db.String(255), nullable=False)
# Job Applications Model

class JobApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("job.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    resume_filename = db.Column(db.String(255), nullable=False)

    # Add relationship to Job model
    job = db.relationship("Job", backref=db.backref("applications", lazy=True))

class HRUser(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


# Job Posting Form
class JobForm(FlaskForm):
    title = StringField("Job Title", validators=[DataRequired()])
    description = TextAreaField("Job Description", validators=[DataRequired()])
    skills = StringField("Required Skills (comma-separated)", validators=[DataRequired()])
    submit = SubmitField("Post Job")
class JobApplicationForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    resume = FileField("Upload Resume (PDF only)", validators=[DataRequired()])
    submit = SubmitField("Apply")

class HRRegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Register")

class HRLoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")





# Configure upload folder
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pdf"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["SECRET_KEY"] = "supersecretkey"  # Required for Flash messages

# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    """Check if the uploaded file is a PDF"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return HRUser.query.get(int(user_id))

@app.route("/register", methods=["GET", "POST"])
def register():
    """HR User Registration"""
    form = HRRegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        user = HRUser(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    """HR User Login"""
    form = HRLoginForm()
    if form.validate_on_submit():
        user = HRUser.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("job_list"))
        else:
            flash("Invalid username or password.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    """HR Logout"""
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
def upload_resume():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part")
            return redirect(request.url)

        file = request.files["file"]

        if file.filename == "":
            flash("No selected file")
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)

            # Process the resume
            matched_skills, match_percentage = process_resume(file_path)

            return render_template("results.html", matched_skills=matched_skills, match_percentage=match_percentage)

    return render_template("upload.html")

@app.route("/jobs", methods=["GET", "POST"])
def job_list():
    """Display jobs and calculate match percentage for uploaded resume"""
    jobs = Job.query.all()
    match_results = {}

    if request.method == "POST" and "resume" in request.files:
        file = request.files["resume"]
        if file.filename.endswith(".pdf"):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)

            # Process resume and extract skills
            matched_skills, _ = process_resume(file_path)

            # Compare resume skills with each job
            for job in jobs:
                job_skills = set(job.skills.split(", "))
                common_skills = matched_skills.intersection(job_skills)
                match_score = (len(common_skills) / len(job_skills)) * 100 if job_skills else 0
                match_results[job.id] = round(match_score, 2)

    return render_template("job_list.html", jobs=jobs, match_results=match_results)

@app.route("/apply/<int:job_id>", methods=["GET", "POST"])
def apply_for_job(job_id):
    """User applies for a job - checks resume matching first"""
    job = Job.query.get_or_404(job_id)
    form = JobApplicationForm()

    if form.validate_on_submit():
        # Save resume file
        file = form.resume.data
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)

        # Parse resume and check match percentage
        from resume_parser import process_resume  # Importing resume parsing function
        matched_skills, match_percentage = process_resume(file_path)

        if match_percentage >= 50:
            # Store application in database
            application = JobApplication(
                job_id=job.id,
                name=form.name.data,
                email=form.email.data,
                resume_filename=filename
            )
            db.session.add(application)
            db.session.commit()

            return redirect(url_for("application_confirmation"))

        else:
            # Find better job matches
            suggested_jobs = []
            all_jobs = Job.query.all()
            for j in all_jobs:
                job_skills = set(j.skills.split(", "))
                common_skills = matched_skills.intersection(job_skills)
                match_score = (len(common_skills) / len(job_skills)) * 100 if job_skills else 0
                if match_score >= 50:
                    suggested_jobs.append(j)

            return render_template("job_suggestions.html", job=job, suggested_jobs=suggested_jobs)

    return render_template("apply.html", form=form, job=job)

@app.route("/delete-application/<int:application_id>", methods=["POST"])
@login_required
def delete_application(application_id):
    """HR can delete a job application"""
    application = JobApplication.query.get_or_404(application_id)

    # Delete the resume file from the uploads folder
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], application.resume_filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    # Delete application from the database
    db.session.delete(application)
    db.session.commit()
    flash("Application deleted successfully!", "success")

    return redirect(url_for("view_applications"))



@app.route("/uploads/<filename>")
def uploaded_file(filename):
    """Serve uploaded resumes"""
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)



@app.route("/post-job", methods=["GET", "POST"])
@login_required
def post_job():
    """HR can post a job"""
    form = JobForm()
    if form.validate_on_submit():
        job = Job(title=form.title.data, description=form.description.data, skills=form.skills.data.lower())
        db.session.add(job)
        db.session.commit()
        flash("Job posted successfully!", "success")
        return redirect(url_for("job_list"))
    return render_template("post_job.html", form=form)

@app.route("/applications")
@login_required
def view_applications():
    """HR can view job applications"""
    applications = JobApplication.query.all()
    return render_template("applications.html", applications=applications)

@app.route("/application-confirmation")
def application_confirmation():
    """Show confirmation page after successful application submission"""
    return render_template("confirmation.html")

if __name__ == "__main__":
    app.run(debug=True)
