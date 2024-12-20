from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
from functools import wraps
from sqlalchemy import or_, func
from math import radians, cos, sin, asin, sqrt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///startup_teams.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# OAuth Configuration
oauth = OAuth(app)

# Google OAuth Config
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
)

# GitHub OAuth Config
github = oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

# Add configuration for file uploads
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    social_id = db.Column(db.String(128), unique=True)  # For social login
    social_provider = db.Column(db.String(20))  # e.g., 'google', 'github'
    profile_picture = db.Column(db.String(200))
    bio = db.Column(db.Text)
    skills = db.Column(db.JSON)  # {"technical": [], "design": [], "marketing": [], "management": []}
    interests = db.Column(db.JSON)  # Store project preferences and interests as JSON
    experience = db.Column(db.JSON)  # Store work experience as structured data
    education = db.Column(db.JSON)  # Store education history
    certificates = db.Column(db.JSON)  # Store certificates with links and descriptions
    location = db.Column(db.String(200))  # Add location field
    latitude = db.Column(db.Float)  # Add latitude for geographic matching
    longitude = db.Column(db.Float)  # Add longitude for geographic matching
    linkedin_url = db.Column(db.String(200))
    github_url = db.Column(db.String(200))
    portfolio_url = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    teams = db.relationship('Team', secondary='team_members', backref='members')
    created_teams = db.relationship('Team', backref='creator', lazy=True, foreign_keys='Team.creator_id')
    created_projects = db.relationship('Project', backref='creator', lazy=True, foreign_keys='Project.creator_id')
    project_memberships = db.relationship('ProjectMember', backref='user', lazy=True)

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    sector = db.Column(db.String(50), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    goals = db.Column(db.JSON)  # List of project goals
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    status = db.Column(db.String(20), default='open')  # open, in_progress, completed, cancelled
    required_roles = db.Column(db.JSON)  # List of required roles with descriptions
    team_members = db.relationship('ProjectMember', backref='project', lazy=True)

class ProjectMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

team_members = db.Table('team_members',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('team_id', db.Integer, db.ForeignKey('team.id'), primary_key=True)
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    teams = Team.query.order_by(Team.created_at.desc()).all()
    return render_template('index.html', teams=teams)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('خطأ في اسم المستخدم أو كلمة المرور')
            
    return render_template('login.html')

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorize')
def google_authorize():
    try:
        token = google.authorize_access_token()
        resp = google.get('userinfo')
        user_info = resp.json()
        
        # Check if user exists
        user = User.query.filter_by(email=user_info['email']).first()
        if not user:
            # Create new user
            user = User(
                username=user_info['email'].split('@')[0],
                email=user_info['email'],
                social_id=user_info['id'],
                social_provider='google'
            )
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        return redirect(url_for('index'))
    except Exception as e:
        flash('حدث خطأ أثناء تسجيل الدخول باستخدام Google', 'error')
        return redirect(url_for('login'))

@app.route('/login/github')
def github_login():
    redirect_uri = url_for('github_authorize', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/login/github/authorize')
def github_authorize():
    try:
        token = github.authorize_access_token()
        resp = github.get('user')
        user_info = resp.json()
        
        # Get user's email
        emails_resp = github.get('user/emails')
        emails = emails_resp.json()
        primary_email = next(email['email'] for email in emails if email['primary'])
        
        # Check if user exists
        user = User.query.filter_by(email=primary_email).first()
        if not user:
            # Create new user
            user = User(
                username=user_info['login'],
                email=primary_email,
                social_id=str(user_info['id']),
                social_provider='github'
            )
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        return redirect(url_for('index'))
    except Exception as e:
        flash('حدث خطأ أثناء تسجيل الدخول باستخدام GitHub', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/create_team', methods=['GET', 'POST'])
@login_required
def create_team():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        sector = request.form.get('sector')
        
        team = Team(name=name, description=description, sector=sector, creator=current_user)
        team.members.append(current_user)
        
        db.session.add(team)
        db.session.commit()
        
        flash('تم إنشاء الفريق بنجاح!')
        return redirect(url_for('index'))
        
    return render_template('create_team.html')

@app.route('/team/<int:team_id>')
def team_details(team_id):
    team = Team.query.get_or_404(team_id)
    return render_template('team_details.html', team=team)

@app.route('/join_team/<int:team_id>')
@login_required
def join_team(team_id):
    team = Team.query.get_or_404(team_id)
    if current_user not in team.members:
        team.members.append(current_user)
        db.session.commit()
        flash('تم الانضمام للفريق بنجاح!')
    return redirect(url_for('team_details', team_id=team_id))

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('profile.html', user=user)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        # Handle profile picture upload
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                current_user.profile_picture = filename

        # Update basic information
        current_user.bio = request.form.get('bio', '')
        current_user.linkedin_url = request.form.get('linkedin_url', '')
        current_user.github_url = request.form.get('github_url', '')
        current_user.portfolio_url = request.form.get('portfolio_url', '')

        # Update skills (as JSON)
        skills = {
            'technical': request.form.getlist('technical_skills[]'),
            'design': request.form.getlist('design_skills[]'),
            'marketing': request.form.getlist('marketing_skills[]'),
            'management': request.form.getlist('management_skills[]')
        }
        current_user.skills = skills

        # Update interests (as JSON)
        interests = request.form.getlist('interests[]')
        current_user.interests = interests

        # Update experience (as JSON)
        experience = []
        exp_titles = request.form.getlist('exp_title[]')
        exp_companies = request.form.getlist('exp_company[]')
        exp_dates = request.form.getlist('exp_date[]')
        exp_descriptions = request.form.getlist('exp_description[]')
        
        for i in range(len(exp_titles)):
            if exp_titles[i]:  # Only add if title exists
                experience.append({
                    'title': exp_titles[i],
                    'company': exp_companies[i],
                    'date': exp_dates[i],
                    'description': exp_descriptions[i]
                })
        current_user.experience = experience

        # Update certificates (as JSON)
        certificates = []
        cert_names = request.form.getlist('cert_name[]')
        cert_issuers = request.form.getlist('cert_issuer[]')
        cert_dates = request.form.getlist('cert_date[]')
        cert_urls = request.form.getlist('cert_url[]')
        
        for i in range(len(cert_names)):
            if cert_names[i]:  # Only add if name exists
                certificates.append({
                    'name': cert_names[i],
                    'issuer': cert_issuers[i],
                    'date': cert_dates[i],
                    'url': cert_urls[i]
                })
        current_user.certificates = certificates

        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile', username=current_user.username))

    return render_template('edit_profile.html')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def haversine_distance(lat1, lon1, lat2, lon2):
    """Calculate the great circle distance between two points on the earth"""
    # Convert decimal degrees to radians
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    # Radius of earth in kilometers
    r = 6371
    return c * r

@app.route('/search')
def search():
    query = request.args.get('q', '')
    skills = request.args.get('skills', '')
    location = request.args.get('location', '')
    
    users = User.query
    
    if query:
        users = users.filter(or_(
            User.username.ilike(f'%{query}%'),
            User.bio.ilike(f'%{query}%')
        ))
    
    if skills:
        skills_list = [skill.strip() for skill in skills.split(',')]
        users = users.filter(User.skills.cast(db.String).ilike(
            func.concat('%', func.json_array(skills_list), '%')
        ))
    
    if location:
        # Filter by location name
        users = users.filter(User.location.ilike(f'%{location}%'))
    
    users = users.all()
    return render_template('search_results.html', users=users)

@app.route('/match_suggestions')
@login_required
def match_suggestions():
    # Get current user's skills and interests
    user_skills = current_user.skills or {}
    user_location = current_user.location
    user_lat = current_user.latitude
    user_lon = current_user.longitude
    
    # Find potential matches
    potential_matches = User.query.filter(User.id != current_user.id).all()
    
    # Score and sort matches
    scored_matches = []
    for match in potential_matches:
        score = 0
        match_skills = match.skills or {}
        
        # Calculate skill match score
        if user_skills and match_skills:
            common_skills = set(str(user_skills).lower().split()) & set(str(match_skills).lower().split())
            score += len(common_skills) * 10
        
        # Calculate location proximity score if coordinates available
        if all([user_lat, user_lon, match.latitude, match.longitude]):
            distance = haversine_distance(user_lat, user_lon, match.latitude, match.longitude)
            # Give higher score for closer locations (max 50 points for same location)
            proximity_score = max(0, 50 - (distance / 10))  # Decrease score by 1 point per 10km
            score += proximity_score
        
        scored_matches.append({
            'user': match,
            'score': score
        })
    
    # Sort by score and get top matches
    scored_matches.sort(key=lambda x: x['score'], reverse=True)
    top_matches = scored_matches[:10]  # Get top 10 matches
    
    return render_template('match_suggestions.html', matches=top_matches)

# Add project routes
@app.route('/projects')
def projects():
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template('projects/index.html', projects=projects)

@app.route('/projects/create', methods=['GET', 'POST'])
@login_required
def create_project():
    if request.method == 'POST':
        goals = request.form.getlist('goals[]')
        required_roles = []
        
        # Process required roles from form
        role_titles = request.form.getlist('role_title[]')
        role_descriptions = request.form.getlist('role_description[]')
        for i in range(len(role_titles)):
            if role_titles[i].strip():  # Only add if title is not empty
                required_roles.append({
                    'title': role_titles[i],
                    'description': role_descriptions[i]
                })
        
        project = Project(
            title=request.form['title'],
            description=request.form['description'],
            goals=goals,
            creator_id=current_user.id,
            start_date=datetime.strptime(request.form['start_date'], '%Y-%m-%d').date(),
            end_date=datetime.strptime(request.form['end_date'], '%Y-%m-%d').date(),
            required_roles=required_roles
        )
        
        db.session.add(project)
        db.session.commit()
        
        flash('تم إنشاء المشروع بنجاح!', 'success')
        return redirect(url_for('project_details', project_id=project.id))
    
    return render_template('projects/create.html')

@app.route('/projects/<int:project_id>')
def project_details(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template('projects/details.html', project=project)

@app.route('/projects/<int:project_id>/apply/<string:role>', methods=['POST'])
@login_required
def apply_to_project(project_id, role):
    project = Project.query.get_or_404(project_id)
    
    # Check if user already applied
    existing_application = ProjectMember.query.filter_by(
        project_id=project_id,
        user_id=current_user.id
    ).first()
    
    if existing_application:
        flash('لقد تقدمت بالفعل لهذا المشروع.', 'warning')
    else:
        application = ProjectMember(
            project_id=project_id,
            user_id=current_user.id,
            role=role
        )
        db.session.add(application)
        db.session.commit()
        flash('تم تقديم طلبك بنجاح!', 'success')
    
    return redirect(url_for('project_details', project_id=project_id))

@app.route('/projects/<int:project_id>/applications')
@login_required
def project_applications(project_id):
    project = Project.query.get_or_404(project_id)
    if project.creator_id != current_user.id:
        abort(403)
    return render_template('projects/applications.html', project=project)

@app.route('/projects/<int:project_id>/application/<int:application_id>/<string:action>', methods=['POST'])
@login_required
def handle_application(project_id, application_id, action):
    project = Project.query.get_or_404(project_id)
    if project.creator_id != current_user.id:
        abort(403)
        
    application = ProjectMember.query.get_or_404(application_id)
    if action == 'accept':
        application.status = 'accepted'
        flash('تم قبول الطلب بنجاح!', 'success')
    elif action == 'reject':
        application.status = 'rejected'
        flash('تم رفض الطلب.', 'info')
        
    db.session.commit()
    return redirect(url_for('project_applications', project_id=project_id))

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()  # Clear existing tables
        db.create_all()  # Create new tables with updated schema
        
        # Create a test user if needed
        test_user = User(
            username="test_user",
            email="test@example.com",
            location="New York",
            latitude=40.7128,
            longitude=-74.0060
        )
        test_user.set_password("test123")
        test_user.skills = ["Python", "JavaScript", "Flask"]
        test_user.interests = ["Web Development", "AI", "Mobile Apps"]
        
        db.session.add(test_user)
        db.session.commit()
        
    app.run(debug=True, port=8080)
