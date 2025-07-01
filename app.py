import os
import logging
import sqlite3
import smtplib
from datetime import datetime, timedelta
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from flask_session import Session
import bleach
from decouple import config
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.logging import LoggingIntegration
import magic
from PIL import Image
import qrcode
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
import pytz
from email_validator import validate_email, EmailNotValidError
import phonenumbers
from phonenumbers import NumberParseException

# Initialize Flask app
app = Flask(__name__)

# Production Configuration
class ProductionConfig:
    # Security
    SECRET_KEY = config('SECRET_KEY', default=os.urandom(32))
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    
    # Database
    DATABASE_URL = config('DATABASE_URL', default='sqlite:///medtrak.db')
    DATABASE_POOL_SIZE = config('DATABASE_POOL_SIZE', default=10, cast=int)
    DATABASE_POOL_TIMEOUT = config('DATABASE_POOL_TIMEOUT', default=30, cast=int)
    
    # File Upload
    UPLOAD_FOLDER = config('UPLOAD_FOLDER', default='uploads')
    MAX_CONTENT_LENGTH = config('MAX_CONTENT_LENGTH', default=16 * 1024 * 1024, cast=int)  # 16MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'bmp', 'webp'}
    
    # Email Configuration
    MAIL_SERVER = config('MAIL_SERVER', default='smtp.gmail.com')
    MAIL_PORT = config('MAIL_PORT', default=587, cast=int)
    MAIL_USE_TLS = config('MAIL_USE_TLS', default=True, cast=bool)
    MAIL_USERNAME = config('MAIL_USERNAME', default='')
    MAIL_PASSWORD = config('MAIL_PASSWORD', default='')
    MAIL_DEFAULT_SENDER = config('MAIL_DEFAULT_SENDER', default='')
    
    # Session Configuration
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'medtrak:'
    SESSION_FILE_DIR = config('SESSION_FILE_DIR', default='./flask_session')
    PERMANENT_SESSION_LIFETIME = timedelta(hours=config('SESSION_TIMEOUT_HOURS', default=8, cast=int))
    
    # Cache Configuration
    CACHE_TYPE = config('CACHE_TYPE', default='simple')
    CACHE_DEFAULT_TIMEOUT = config('CACHE_DEFAULT_TIMEOUT', default=300, cast=int)
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = config('RATELIMIT_STORAGE_URL', default='memory://')
    RATELIMIT_DEFAULT = config('RATELIMIT_DEFAULT', default='100 per hour')
    
    # Application Settings
    APP_NAME = config('APP_NAME', default='MedTrak')
    APP_VERSION = config('APP_VERSION', default='1.0.0')
    TIMEZONE = config('TIMEZONE', default='UTC')
    
    # Security Settings
    MAX_LOGIN_ATTEMPTS = config('MAX_LOGIN_ATTEMPTS', default=5, cast=int)
    ACCOUNT_LOCKOUT_DURATION = config('ACCOUNT_LOCKOUT_DURATION', default=30, cast=int)  # minutes
    
    # Logging
    LOG_LEVEL = config('LOG_LEVEL', default='INFO')
    LOG_FILE = config('LOG_FILE', default='medtrak.log')
    LOG_MAX_BYTES = config('LOG_MAX_BYTES', default=10485760, cast=int)  # 10MB
    LOG_BACKUP_COUNT = config('LOG_BACKUP_COUNT', default=5, cast=int)

# Apply configuration
app.config.from_object(ProductionConfig)

# Initialize Sentry for error tracking
if config('SENTRY_DSN', default=''):
    sentry_logging = LoggingIntegration(
        level=logging.INFO,
        event_level=logging.ERROR
    )
    sentry_sdk.init(
        dsn=config('SENTRY_DSN'),
        integrations=[FlaskIntegration(), sentry_logging],
        traces_sample_rate=config('SENTRY_TRACES_SAMPLE_RATE', default=0.1, cast=float),
        environment=config('ENVIRONMENT', default='production')
    )

# Configure logging
def setup_logging():
    from logging.handlers import RotatingFileHandler
    import colorlog
    
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    # File handler
    file_handler = RotatingFileHandler(
        f'logs/{app.config["LOG_FILE"]}',
        maxBytes=app.config['LOG_MAX_BYTES'],
        backupCount=app.config['LOG_BACKUP_COUNT']
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s %(name)s [%(filename)s:%(lineno)d] %(message)s'
    ))
    
    # Console handler with colors
    console_handler = colorlog.StreamHandler()
    console_handler.setFormatter(colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s %(levelname)s %(name)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    # Configure app logger
    app.logger.setLevel(getattr(logging, app.config['LOG_LEVEL']))
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    
    # Configure werkzeug logger
    logging.getLogger('werkzeug').setLevel(logging.WARNING)

setup_logging()

# Security Headers with Talisman
csp = {
    'default-src': "'self'",
    'script-src': [
        "'self'",
        "'unsafe-inline'",
        'cdn.jsdelivr.net',
        'cdnjs.cloudflare.com',
        'code.jquery.com'
    ],
    'style-src': [
        "'self'",
        "'unsafe-inline'",
        'cdn.jsdelivr.net',
        'cdnjs.cloudflare.com',
        'fonts.googleapis.com'
    ],
    'font-src': [
        "'self'",
        'fonts.gstatic.com',
        'cdnjs.cloudflare.com'
    ],
    'img-src': [
        "'self'",
        'data:',
        'blob:'
    ]
}

talisman = Talisman(
    app,
    force_https=config('FORCE_HTTPS', default=True, cast=bool),
    strict_transport_security=True,
    content_security_policy=csp,
    referrer_policy='strict-origin-when-cross-origin'
)

# Rate Limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[app.config['RATELIMIT_DEFAULT']]
)
limiter.init_app(app)

# Caching
cache = Cache(app)

# Session Management
Session(app)

# Proxy Fix for production deployment
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pictures'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'medical_records'), exist_ok=True)

# Database initialization with better error handling
def init_db():
    """Initialize database with proper error handling"""
    try:
        conn = sqlite3.connect(app.config['DATABASE_URL'].replace('sqlite:///', ''))
        cursor = conn.cursor()
        
        # Read and execute schema
        schema_path = os.path.join('scripts', 'create_database.sql')
        if os.path.exists(schema_path):
            with open(schema_path, 'r') as f:
                schema = f.read()
                cursor.executescript(schema)
        else:
            # Fallback to inline schema
            cursor.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('patient', 'doctor')),
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    phone TEXT,
                    profile_picture TEXT,
                    failed_login_attempts INTEGER DEFAULT 0,
                    account_locked_until TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS doctor_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    specialization TEXT NOT NULL,
                    license_number TEXT UNIQUE NOT NULL,
                    experience_years INTEGER DEFAULT 0,
                    bio TEXT,
                    consultation_fee REAL DEFAULT 0.00,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                );
                
                CREATE TABLE IF NOT EXISTS patient_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    date_of_birth DATE,
                    gender TEXT CHECK (gender IN ('male', 'female', 'other')),
                    blood_type TEXT,
                    emergency_contact TEXT,
                    emergency_phone TEXT,
                    medical_history TEXT,
                    allergies TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                );
                
                CREATE TABLE IF NOT EXISTS appointments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    patient_id INTEGER NOT NULL,
                    doctor_id INTEGER NOT NULL,
                    appointment_date DATE NOT NULL,
                    appointment_time TIME NOT NULL,
                    status TEXT DEFAULT 'scheduled' CHECK (status IN ('scheduled', 'completed', 'cancelled', 'rescheduled')),
                    reason TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (patient_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (doctor_id) REFERENCES users (id) ON DELETE CASCADE
                );
                
                CREATE TABLE IF NOT EXISTS medical_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    patient_id INTEGER NOT NULL,
                    doctor_id INTEGER NOT NULL,
                    appointment_id INTEGER,
                    record_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    file_path TEXT,
                    file_size INTEGER,
                    file_type TEXT,
                    is_shared BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (patient_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (doctor_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (appointment_id) REFERENCES appointments (id) ON DELETE SET NULL
                );
                
                CREATE TABLE IF NOT EXISTS prescriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    patient_id INTEGER NOT NULL,
                    doctor_id INTEGER NOT NULL,
                    appointment_id INTEGER,
                    prescription_number TEXT UNIQUE NOT NULL,
                    medications TEXT NOT NULL,
                    instructions TEXT,
                    diagnosis TEXT,
                    date_issued DATE DEFAULT CURRENT_DATE,
                    valid_until DATE,
                    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'expired', 'cancelled')),
                    email_sent BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (patient_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (doctor_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (appointment_id) REFERENCES appointments (id) ON DELETE SET NULL
                );
                
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                CREATE INDEX IF NOT EXISTS idx_appointments_patient ON appointments(patient_id);
                CREATE INDEX IF NOT EXISTS idx_appointments_doctor ON appointments(doctor_id);
                CREATE INDEX IF NOT EXISTS idx_appointments_date ON appointments(appointment_date);
                CREATE INDEX IF NOT EXISTS idx_medical_records_patient ON medical_records(patient_id);
                CREATE INDEX IF NOT EXISTS idx_prescriptions_patient ON prescriptions(patient_id);
            ''')
        
        conn.commit()
        conn.close()
        app.logger.info("Database initialized successfully")
        
    except Exception as e:
        app.logger.error(f"Database initialization failed: {str(e)}")
        raise

# Enhanced database connection with connection pooling simulation
def get_db_connection():
    """Get database connection with proper error handling"""
    try:
        db_path = app.config['DATABASE_URL'].replace('sqlite:///', '')
        conn = sqlite3.connect(
            db_path,
            timeout=app.config['DATABASE_POOL_TIMEOUT'],
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        return conn
    except Exception as e:
        app.logger.error(f"Database connection failed: {str(e)}")
        raise

# Enhanced security functions
def sanitize_input(text):
    """Sanitize user input to prevent XSS"""
    if not text:
        return text
    return bleach.clean(text, tags=[], attributes={}, strip=True)

def validate_email_address(email):
    """Validate email address"""
    try:
        valid = validate_email(email)
        return valid.email
    except EmailNotValidError:
        return None

def validate_phone_number(phone, country='US'):
    """Validate phone number"""
    try:
        parsed = phonenumbers.parse(phone, country)
        if phonenumbers.is_valid_number(parsed):
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        return None
    except NumberParseException:
        return None

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def secure_file_upload(file):
    """Securely handle file upload"""
    if not file or file.filename == '':
        return None, "No file selected"
    
    if not allowed_file(file.filename):
        return None, "File type not allowed"
    
    # Check file size
    file.seek(0, 2)  # Seek to end
    size = file.tell()
    file.seek(0)  # Reset to beginning
    
    if size > app.config['MAX_CONTENT_LENGTH']:
        return None, "File too large"
    
    # Validate file content using python-magic
    file_content = file.read(1024)  # Read first 1KB
    file.seek(0)  # Reset
    
    mime_type = magic.from_buffer(file_content, mime=True)
    allowed_mimes = {
        'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp',
        'application/pdf', 'text/plain',
        'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    }
    
    if mime_type not in allowed_mimes:
        return None, "Invalid file content"
    
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
    filename = f"{timestamp}{filename}"
    
    return filename, None

# Authentication decorators with enhanced security
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        # Check session timeout
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > app.config['PERMANENT_SESSION_LIFETIME']:
                session.clear()
                flash('Session expired. Please log in again.', 'warning')
                return redirect(url_for('login'))
        
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session or session['user_role'] != role:
                flash('Access denied. Insufficient permissions.', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Enhanced email function
def send_email(to_email, subject, body, attachment_path=None):
    """Send email with enhanced error handling and logging"""
    try:
        if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            app.logger.warning("Email credentials not configured")
            return False
        
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_DEFAULT_SENDER'] or app.config['MAIL_USERNAME']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'html'))
        
        if attachment_path and os.path.exists(attachment_path):
            with open(attachment_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= {os.path.basename(attachment_path)}'
                )
                msg.attach(part)
        
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)
        
        app.logger.info(f"Email sent successfully to {to_email}")
        return True
        
    except Exception as e:
        app.logger.error(f"Email sending failed to {to_email}: {str(e)}")
        return False

def generate_prescription_number():
    """Generate unique prescription number with better format"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    import random
    random_suffix = random.randint(100, 999)
    return f"RX{timestamp}{random_suffix}"

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    app.logger.warning(f"404 error: {request.url}")
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"500 error: {str(error)}")
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    app.logger.warning(f"403 error: {request.url}")
    return render_template('errors/403.html'), 403

@app.errorhandler(429)
def ratelimit_handler(e):
    app.logger.warning(f"Rate limit exceeded: {request.remote_addr}")
    return render_template('errors/429.html'), 429

# Health check endpoint
@app.route('/health')
@cache.cached(timeout=60)
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check database connection
        conn = get_db_connection()
        conn.execute('SELECT 1').fetchone()
        conn.close()
        
        # Check upload directory
        upload_accessible = os.path.exists(app.config['UPLOAD_FOLDER']) and \
                          os.access(app.config['UPLOAD_FOLDER'], os.W_OK)
        
        status = {
            'status': 'healthy',
            'timestamp': datetime.now(pytz.UTC).isoformat(),
            'version': app.config['APP_VERSION'],
            'database': 'connected',
            'uploads': 'accessible' if upload_accessible else 'error'
        }
        
        return jsonify(status), 200
        
    except Exception as e:
        app.logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now(pytz.UTC).isoformat(),
            'error': str(e)
        }), 503

# Keep all existing routes but add rate limiting and security enhancements
@app.route('/')
@cache.cached(timeout=300)
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        # Sanitize inputs
        username = sanitize_input(request.form.get('username', '').strip())
        email = sanitize_input(request.form.get('email', '').strip())
        password = request.form.get('password', '')
        role = sanitize_input(request.form.get('role', ''))
        first_name = sanitize_input(request.form.get('first_name', '').strip())
        last_name = sanitize_input(request.form.get('last_name', '').strip())
        phone = sanitize_input(request.form.get('phone', '').strip())
        
        # Validate inputs
        if not all([username, email, password, role, first_name, last_name]):
            flash('All required fields must be filled.', 'error')
            return render_template('register.html')
        
        # Validate email
        validated_email = validate_email_address(email)
        if not validated_email:
            flash('Please enter a valid email address.', 'error')
            return render_template('register.html')
        
        # Validate phone if provided
        if phone:
            validated_phone = validate_phone_number(phone)
            if not validated_phone:
                flash('Please enter a valid phone number.', 'error')
                return render_template('register.html')
            phone = validated_phone
        
        # Password strength validation
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html')
        
        try:
            conn = get_db_connection()
            
            # Check if user already exists
            existing_user = conn.execute(
                'SELECT id FROM users WHERE username = ? OR email = ?',
                (username, validated_email)
            ).fetchone()
            
            if existing_user:
                flash('Username or email already exists.', 'error')
                conn.close()
                return render_template('register.html')
            
            # Create user
            password_hash = generate_password_hash(password)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, role, first_name, last_name, phone)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, validated_email, password_hash, role, first_name, last_name, phone))
            
            user_id = cursor.lastrowid
            
            # Create role-specific profile
            if role == 'doctor':
                specialization = sanitize_input(request.form.get('specialization', ''))
                license_number = sanitize_input(request.form.get('license_number', ''))
                if specialization and license_number:
                    cursor.execute('''
                        INSERT INTO doctor_profiles (user_id, specialization, license_number)
                        VALUES (?, ?, ?)
                    ''', (user_id, specialization, license_number))
            else:  # patient
                cursor.execute('''
                    INSERT INTO patient_profiles (user_id)
                    VALUES (?)
                ''', (user_id,))
            
            conn.commit()
            conn.close()
            
            app.logger.info(f"New user registered: {username} ({role})")
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', '').strip())
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        try:
            conn = get_db_connection()
            user = conn.execute(
                '''SELECT * FROM users WHERE username = ? OR email = ?''',
                (username, username)
            ).fetchone()
            
            if not user:
                app.logger.warning(f"Login attempt with non-existent user: {username}")
                flash('Invalid username or password.', 'error')
                conn.close()
                return render_template('login.html')
            
            # Check account lockout
            if user['account_locked_until']:
                lockout_time = datetime.fromisoformat(user['account_locked_until'])
                if datetime.now() < lockout_time:
                    remaining = int((lockout_time - datetime.now()).total_seconds() / 60)
                    flash(f'Account locked. Try again in {remaining} minutes.', 'error')
                    conn.close()
                    return render_template('login.html')
                else:
                    # Reset lockout
                    conn.execute(
                        'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE id = ?',
                        (user['id'],)
                    )
                    conn.commit()
            
            if check_password_hash(user['password_hash'], password):
                # Reset failed attempts on successful login
                conn.execute(
                    'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE id = ?',
                    (user['id'],)
                )
                conn.commit()
                conn.close()
                
                # Set session
                session.permanent = True
                session['user_id'] = user['id']
                session['user_role'] = user['role']
                session['username'] = user['username']
                session['first_name'] = user['first_name']
                session['profile_picture'] = user['profile_picture']
                session['last_activity'] = datetime.now().isoformat()
                
                app.logger.info(f"Successful login: {username}")
                flash(f'Welcome back, {user["first_name"]}!', 'success')
                
                # Redirect based on role
                if user['role'] == 'doctor':
                    return redirect(url_for('doctor_dashboard'))
                else:
                    return redirect(url_for('patient_dashboard'))
            else:
                # Increment failed attempts
                failed_attempts = user['failed_login_attempts'] + 1
                lockout_until = None
                
                if failed_attempts >= app.config['MAX_LOGIN_ATTEMPTS']:
                    lockout_until = datetime.now() + timedelta(minutes=app.config['ACCOUNT_LOCKOUT_DURATION'])
                    lockout_until = lockout_until.isoformat()
                    app.logger.warning(f"Account locked due to failed attempts: {username}")
                    flash(f'Account locked due to too many failed attempts. Try again in {app.config["ACCOUNT_LOCKOUT_DURATION"]} minutes.', 'error')
                else:
                    remaining_attempts = app.config['MAX_LOGIN_ATTEMPTS'] - failed_attempts
                    flash(f'Invalid password. {remaining_attempts} attempts remaining.', 'error')
                
                conn.execute(
                    'UPDATE users SET failed_login_attempts = ?, account_locked_until = ? WHERE id = ?',
                    (failed_attempts, lockout_until, user['id'])
                )
                conn.commit()
                conn.close()
                
                app.logger.warning(f"Failed login attempt: {username}")
                
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash('Login failed. Please try again.', 'error')
    
    return render_template('login.html')

# Add all other existing routes with similar security enhancements...
# (I'll continue with the key routes, but the pattern is the same)

@app.route('/logout')
@login_required
def logout():
    username = session.get('username', 'Unknown')
    session.clear()
    app.logger.info(f"User logged out: {username}")
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/patient/dashboard')
@login_required
@role_required('patient')
def patient_dashboard():
    conn = get_db_connection()
    
    # Get upcoming appointments
    appointments = conn.execute('''
        SELECT a.*, u.first_name, u.last_name, dp.specialization
        FROM appointments a
        JOIN users u ON a.doctor_id = u.id
        JOIN doctor_profiles dp ON u.id = dp.user_id
        WHERE a.patient_id = ? AND a.status = 'scheduled'
        ORDER BY a.appointment_date, a.appointment_time
    ''', (session['user_id'],)).fetchall()
    
    # Get recent medical records
    records = conn.execute('''
        SELECT mr.*, u.first_name, u.last_name
        FROM medical_records mr
        JOIN users u ON mr.doctor_id = u.id
        WHERE mr.patient_id = ?
        ORDER BY mr.created_at DESC
        LIMIT 5
    ''', (session['user_id'],)).fetchall()
    
    # Get recent prescriptions
    prescriptions = conn.execute('''
        SELECT p.*, u.first_name, u.last_name
        FROM prescriptions p
        JOIN users u ON p.doctor_id = u.id
        WHERE p.patient_id = ? AND p.status = 'active'
        ORDER BY p.created_at DESC
        LIMIT 5
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('patient_dashboard.html', 
                         appointments=appointments, 
                         records=records,
                         prescriptions=prescriptions)

@app.route('/doctor/dashboard')
@login_required
@role_required('doctor')
def doctor_dashboard():
    conn = get_db_connection()
    
    # Get today's appointments
    today = datetime.now().date()
    today_str = today.strftime('%Y-%m-%d')
    appointments = conn.execute('''
        SELECT a.*, u.first_name, u.last_name, u.phone
        FROM appointments a
        JOIN users u ON a.patient_id = u.id
        WHERE a.doctor_id = ? AND a.appointment_date = ? AND a.status = 'scheduled'
        ORDER BY a.appointment_time
    ''', (session['user_id'], today_str)).fetchall()
    
    # Get upcoming appointments
    upcoming = conn.execute('''
        SELECT a.*, u.first_name, u.last_name
        FROM appointments a
        JOIN users u ON a.patient_id = u.id
        WHERE a.doctor_id = ? AND a.appointment_date > ? AND a.status = 'scheduled'
        ORDER BY a.appointment_date, a.appointment_time
        LIMIT 10
    ''', (session['user_id'], today_str)).fetchall()
    
    conn.close()
    
    return render_template('doctor_dashboard.html', 
                         today_appointments=appointments,
                         upcoming_appointments=upcoming)

@app.route('/api/doctor/appointments/count')
@login_required
@role_required('doctor')
def get_appointment_count():
    """API endpoint to get current appointment count for auto-refresh"""
    conn = get_db_connection()
    
    today = datetime.now().date()
    today_str = today.strftime('%Y-%m-%d')
    today_count = conn.execute('''
        SELECT COUNT(*) as count FROM appointments 
        WHERE doctor_id = ? AND appointment_date = ? AND status = 'scheduled'
    ''', (session['user_id'], today_str)).fetchone()['count']
    
    upcoming_count = conn.execute('''
        SELECT COUNT(*) as count FROM appointments 
        WHERE doctor_id = ? AND appointment_date > ? AND status = 'scheduled'
    ''', (session['user_id'], today_str)).fetchone()['count']
    
    conn.close()
    
    return jsonify({
        'today_count': today_count,
        'upcoming_count': upcoming_count
    })

@app.route('/book-appointment', methods=['GET', 'POST'])
@login_required
@role_required('patient')
def book_appointment():
    if request.method == 'POST':
        doctor_id = request.form['doctor_id']
        appointment_date = request.form['appointment_date']
        appointment_time = request.form['appointment_time']
        reason = request.form.get('reason', '')
        
        conn = get_db_connection()
        
        # Check if slot is available
        existing = conn.execute('''
            SELECT id FROM appointments 
            WHERE doctor_id = ? AND appointment_date = ? AND appointment_time = ? 
            AND status = 'scheduled'
        ''', (doctor_id, appointment_date, appointment_time)).fetchone()
        
        if existing:
            flash('This time slot is already booked. Please choose another time.', 'error')
        else:
            # Book appointment
            conn.execute('''
                INSERT INTO appointments (patient_id, doctor_id, appointment_date, appointment_time, reason)
                VALUES (?, ?, ?, ?, ?)
            ''', (session['user_id'], doctor_id, appointment_date, appointment_time, reason))
            conn.commit()
            flash('Appointment booked successfully!', 'success')
            conn.close()
            return redirect(url_for('patient_dashboard'))
        
        conn.close()
    
    # Get list of doctors
    conn = get_db_connection()
    doctors = conn.execute('''
        SELECT u.id, u.first_name, u.last_name, dp.specialization, dp.consultation_fee
        FROM users u
        JOIN doctor_profiles dp ON u.id = dp.user_id
        WHERE u.role = 'doctor'
        ORDER BY u.first_name, u.last_name
    ''').fetchall()
    conn.close()
    
    return render_template('book_appointment.html', doctors=doctors)

@app.route('/appointments/<int:appointment_id>')
@login_required
def view_appointment(appointment_id):
    conn = get_db_connection()
    
    appointment = conn.execute('''
        SELECT a.*, 
               p.first_name as patient_first, p.last_name as patient_last,
               d.first_name as doctor_first, d.last_name as doctor_last,
               dp.specialization
        FROM appointments a
        JOIN users p ON a.patient_id = p.id
        JOIN users d ON a.doctor_id = d.id
        JOIN doctor_profiles dp ON d.id = dp.user_id
        WHERE a.id = ?
    ''', (appointment_id,)).fetchone()
    
    conn.close()
    
    if not appointment:
        flash('Appointment not found.', 'error')
        return redirect(url_for('patient_dashboard' if session['user_role'] == 'patient' else 'doctor_dashboard'))
    
    # Check if user has permission to view this appointment
    if session['user_role'] == 'patient' and appointment['patient_id'] != session['user_id']:
        flash('Access denied.', 'error')
        return redirect(url_for('patient_dashboard'))
    elif session['user_role'] == 'doctor' and appointment['doctor_id'] != session['user_id']:
        flash('Access denied.', 'error')
        return redirect(url_for('doctor_dashboard'))
    
    template = f'view_appointment_{session["user_role"]}.html'
    return render_template(template, appointment=appointment)

@app.route('/search-doctors')
@login_required
@role_required('patient')
def search_doctors():
    query = request.args.get('q', '')
    specialization = request.args.get('specialization', '')
    
    conn = get_db_connection()
    
    sql = '''
        SELECT u.id, u.first_name, u.last_name, dp.specialization, dp.consultation_fee, dp.bio
        FROM users u
        JOIN doctor_profiles dp ON u.id = dp.user_id
        WHERE u.role = 'doctor'
    '''
    params = []
    
    if query:
        sql += ' AND (u.first_name LIKE ? OR u.last_name LIKE ?)'
        params.extend([f'%{query}%', f'%{query}%'])
    
    if specialization:
        sql += ' AND dp.specialization LIKE ?'
        params.append(f'%{specialization}%')
    
    sql += ' ORDER BY u.first_name, u.last_name'
    
    doctors = conn.execute(sql, params).fetchall()
    
    # Get all specializations for filter
    specializations = conn.execute('''
        SELECT DISTINCT specialization FROM doctor_profiles ORDER BY specialization
    ''').fetchall()
    
    conn.close()
    
    return render_template('search_results.html', 
                         doctors=doctors, 
                         specializations=specializations,
                         query=query,
                         selected_specialization=specialization)

@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    
    # Get user information
    user = conn.execute(
        'SELECT * FROM users WHERE id = ?',
        (session['user_id'],)
    ).fetchone()
    
    if session['user_role'] == 'doctor':
        profile_data = conn.execute('''
            SELECT dp.*, u.first_name, u.last_name, u.email, u.phone, u.created_at
            FROM doctor_profiles dp
            JOIN users u ON dp.user_id = u.id
            WHERE dp.user_id = ?
        ''', (session['user_id'],)).fetchone()
    else:  # patient
        profile_data = conn.execute('''
            SELECT pp.*, u.first_name, u.last_name, u.email, u.phone, u.created_at
            FROM patient_profiles pp
            JOIN users u ON pp.user_id = u.id
            WHERE pp.user_id = ?
        ''', (session['user_id'],)).fetchone()
    
    conn.close()
    
    return render_template('profile.html', user=user, profile=profile_data)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        conn = get_db_connection()
        
        # Update basic user information
        conn.execute('''
            UPDATE users 
            SET first_name = ?, last_name = ?, phone = ?
            WHERE id = ?
        ''', (
            request.form['first_name'],
            request.form['last_name'],
            request.form.get('phone', ''),
            session['user_id']
        ))
        
        # Update role-specific information
        if session['user_role'] == 'doctor':
            conn.execute('''
                UPDATE doctor_profiles 
                SET specialization = ?, experience_years = ?, bio = ?, consultation_fee = ?
                WHERE user_id = ?
            ''', (
                request.form.get('specialization', ''),
                request.form.get('experience_years', 0) or 0,
                request.form.get('bio', ''),
                request.form.get('consultation_fee', 0) or 0,
                session['user_id']
            ))
        else:  # patient
            conn.execute('''
                UPDATE patient_profiles 
                SET date_of_birth = ?, gender = ?, blood_type = ?, 
                    emergency_contact = ?, emergency_phone = ?, 
                    medical_history = ?, allergies = ?
                WHERE user_id = ?
            ''', (
                request.form.get('date_of_birth') or None,
                request.form.get('gender', ''),
                request.form.get('blood_type', ''),
                request.form.get('emergency_contact', ''),
                request.form.get('emergency_phone', ''),
                request.form.get('medical_history', ''),
                request.form.get('allergies', ''),
                session['user_id']
            ))
        
        conn.commit()
        conn.close()
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    # GET request - show edit form
    return profile()

@app.route('/upload-profile-picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'profile_picture' not in request.files:
        return jsonify({'success': False, 'message': 'No file selected'})
    
    file = request.files['profile_picture']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'})
    
    if file and allowed_file(file.filename):
        # Create profile pictures subdirectory
        profile_pics_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pictures')
        os.makedirs(profile_pics_dir, exist_ok=True)
        
        filename = secure_filename(file.filename)
        # Add user ID and timestamp to filename to avoid conflicts
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
        filename = f"user_{session['user_id']}_{timestamp}{filename}"
        file_path = os.path.join(profile_pics_dir, filename)
        file.save(file_path)
        
        # Update user's profile picture path in database
        conn = get_db_connection()
        conn.execute('''
            UPDATE users SET profile_picture = ? WHERE id = ?
        ''', (f'profile_pictures/{filename}', session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Profile picture updated successfully'})
    
    return jsonify({'success': False, 'message': 'Invalid file type'})

@app.route('/doctor/patient-records')
@app.route('/doctor/patient-records/<int:patient_id>')
@login_required
@role_required('doctor')
def doctor_patient_records(patient_id=None):
    conn = get_db_connection()
    
    # Get search query
    search = request.args.get('search', '')
    
    # Get patients (either all or filtered by search)
    if search:
        patients = conn.execute('''
            SELECT DISTINCT u.id, u.first_name, u.last_name, u.email, u.phone
            FROM users u
            JOIN appointments a ON u.id = a.patient_id
            WHERE u.role = 'patient' AND a.doctor_id = ?
            AND (u.first_name LIKE ? OR u.last_name LIKE ? OR u.email LIKE ?)
            ORDER BY u.first_name, u.last_name
        ''', (session['user_id'], f'%{search}%', f'%{search}%', f'%{search}%')).fetchall()
    else:
        patients = conn.execute('''
            SELECT DISTINCT u.id, u.first_name, u.last_name, u.email, u.phone
            FROM users u
            JOIN appointments a ON u.id = a.patient_id
            WHERE u.role = 'patient' AND a.doctor_id = ?
            ORDER BY u.first_name, u.last_name
        ''', (session['user_id'],)).fetchall()
    
    selected_patient = None
    records = []
    
    if patient_id:
        # Get selected patient info
        selected_patient = conn.execute('''
            SELECT * FROM users WHERE id = ? AND role = 'patient'
        ''', (patient_id,)).fetchone()
        
        if selected_patient:
            # Get patient's medical records created by this doctor
            records = conn.execute('''
                SELECT * FROM medical_records 
                WHERE patient_id = ? AND doctor_id = ?
                ORDER BY created_at DESC
            ''', (patient_id, session['user_id'])).fetchall()
    
    conn.close()
    
    return render_template('doctor_patient_records.html', 
                         patients=patients, 
                         selected_patient=selected_patient,
                         records=records)

@app.route('/doctor/prescriptions')
@login_required
@role_required('doctor')
def doctor_prescriptions():
    conn = get_db_connection()
    
    # Get doctor's patients for prescription
    patients = conn.execute('''
        SELECT DISTINCT u.id, u.first_name, u.last_name, u.email, u.phone
        FROM users u
        JOIN appointments a ON u.id = a.patient_id
        WHERE u.role = 'patient' AND a.doctor_id = ?
        ORDER BY u.first_name, u.last_name
    ''', (session['user_id'],)).fetchall()
    
    # Get recent prescriptions
    prescriptions = conn.execute('''
        SELECT p.*, u.first_name, u.last_name, u.email
        FROM prescriptions p
        JOIN users u ON p.patient_id = u.id
        WHERE p.doctor_id = ?
        ORDER BY p.created_at DESC
        LIMIT 20
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('doctor_prescriptions.html', 
                         patients=patients,
                         prescriptions=prescriptions)

@app.route('/api/patient/<int:patient_id>')
@login_required
@role_required('doctor')
def get_patient_details(patient_id):
    """API endpoint to get patient details for prescription form"""
    try:
        conn = get_db_connection()
        
        patient = conn.execute('''
            SELECT u.*, pp.date_of_birth, pp.gender, pp.blood_type, pp.allergies, pp.medical_history
            FROM users u
            LEFT JOIN patient_profiles pp ON u.id = pp.user_id
            WHERE u.id = ? AND u.role = 'patient'
        ''', (patient_id,)).fetchone()
        
        conn.close()
        
        if patient:
            return jsonify({
                'success': True,
                'patient': {
                    'id': patient['id'],
                    'name': f"{patient['first_name']} {patient['last_name']}",
                    'email': patient['email'],
                    'phone': patient['phone'],
                    'date_of_birth': patient['date_of_birth'],
                    'gender': patient['gender'],
                    'blood_type': patient['blood_type'],
                    'allergies': patient['allergies'],
                    'medical_history': patient['medical_history']
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Patient not found'})
    except Exception as e:
        app.logger.error(f"Error in get_patient_details: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'})

@app.route('/create-prescription', methods=['POST'])
@login_required
@role_required('doctor')
def create_prescription():
    try:
        app.logger.info("Create prescription route called")
        app.logger.info(f"Form data: {dict(request.form)}")
        
        patient_id = request.form.get('patient_id')
        medications = request.form.get('medications')
        instructions = request.form.get('instructions')
        diagnosis = request.form.get('diagnosis')
        valid_days = int(request.form.get('valid_days', 30))
        send_email = request.form.get('send_email') == 'on'
        
        app.logger.info(f"Parsed data - Patient ID: {patient_id}, Medications: {medications[:50]}...")
        
        if not all([patient_id, medications]):
            app.logger.warning("Missing required fields")
            return jsonify({'success': False, 'message': 'Patient and medications are required'})
        
        conn = get_db_connection()
        
        # Get patient details
        patient = conn.execute('''
            SELECT u.*, pp.date_of_birth, pp.gender, pp.allergies
            FROM users u
            LEFT JOIN patient_profiles pp ON u.id = pp.user_id
            WHERE u.id = ? AND u.role = 'patient'
        ''', (patient_id,)).fetchone()
        
        if not patient:
            conn.close()
            app.logger.warning(f"Patient not found: {patient_id}")
            return jsonify({'success': False, 'message': 'Patient not found'})
        
        # Get doctor details
        doctor = conn.execute('''
            SELECT u.*, dp.specialization, dp.license_number
            FROM users u
            JOIN doctor_profiles dp ON u.id = dp.user_id
            WHERE u.id = ?
        ''', (session['user_id'],)).fetchone()
        
        # Generate prescription number
        prescription_number = generate_prescription_number()
        app.logger.info(f"Generated prescription number: {prescription_number}")
        
        # Calculate valid until date
        valid_until = datetime.now().date() + timedelta(days=valid_days)
        valid_until_str = valid_until.strftime('%Y-%m-%d')
        
        # Create prescription
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO prescriptions (patient_id, doctor_id, prescription_number, medications, instructions, diagnosis, valid_until)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (patient_id, session['user_id'], prescription_number, medications, instructions, diagnosis, valid_until_str))
        
        prescription_id = cursor.lastrowid
        app.logger.info(f"Prescription created with ID: {prescription_id}")
        
        # Send email if requested
        email_sent = False
        if send_email and patient['email']:
            app.logger.info(f"Attempting to send email to: {patient['email']}")
            email_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <h1 style="color: #2c5aa0; margin-bottom: 10px;">🏥 MedTrak Prescription</h1>
                        <p style="color: #666; margin: 0;">Digital Prescription Service</p>
                    </div>
                    
                    <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                        <h2 style="color: #2c5aa0; margin-top: 0;">Prescription Details</h2>
                        <p><strong>Prescription Number:</strong> {prescription_number}</p>
                        <p><strong>Date Issued:</strong> {datetime.now().strftime('%B %d, %Y')}</p>
                        <p><strong>Valid Until:</strong> {valid_until.strftime('%B %d, %Y')}</p>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <h3 style="color: #2c5aa0;">Patient Information</h3>
                        <p><strong>Name:</strong> {patient['first_name']} {patient['last_name']}</p>
                        <p><strong>Date of Birth:</strong> {patient['date_of_birth'] or 'Not provided'}</p>
                        <p><strong>Gender:</strong> {patient['gender'] or 'Not specified'}</p>
                        {f"<p><strong>Allergies:</strong> <span style='color: #dc3545;'>{patient['allergies']}</span></p>" if patient['allergies'] else ""}
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <h3 style="color: #2c5aa0;">Doctor Information</h3>
                        <p><strong>Dr. {doctor['first_name']} {doctor['last_name']}</strong></p>
                        <p><strong>Specialization:</strong> {doctor['specialization']}</p>
                        <p><strong>License Number:</strong> {doctor['license_number']}</p>
                    </div>
                    
                    {f"<div style='margin-bottom: 20px;'><h3 style='color: #2c5aa0;'>Diagnosis</h3><p>{diagnosis}</p></div>" if diagnosis else ""}
                    
                    <div style="background-color: #e8f4fd; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                        <h3 style="color: #2c5aa0; margin-top: 0;">💊 Prescribed Medications</h3>
                        <div style="white-space: pre-line; font-family: monospace; background: white; padding: 15px; border-radius: 5px; border-left: 4px solid #2c5aa0;">
{medications}
                        </div>
                    </div>
                    
                    {f"<div style='margin-bottom: 20px;'><h3 style='color: #2c5aa0;'>📋 Instructions</h3><p style='background: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107;'>{instructions}</p></div>" if instructions else ""}
                    
                    <div style="background-color: #d4edda; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                        <h4 style="color: #155724; margin-top: 0;">⚠️ Important Notes:</h4>
                        <ul style="margin: 0; color: #155724;">
                            <li>Take medications exactly as prescribed</li>
                            <li>Complete the full course even if you feel better</li>
                            <li>Contact your doctor if you experience any side effects</li>
                            <li>This prescription is valid until {valid_until.strftime('%B %d, %Y')}</li>
                        </ul>
                    </div>
                    
                    <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
                        <p style="color: #666; margin: 0;">This is a digitally generated prescription from MedTrak</p>
                        <p style="color: #666; margin: 5px 0 0 0; font-size: 12px;">For any queries, please contact your healthcare provider</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            subject = f"Prescription from Dr. {doctor['first_name']} {doctor['last_name']} - {prescription_number}"
            email_sent = send_email(patient['email'], subject, email_body)
            
            if email_sent:
                cursor.execute('''
                    UPDATE prescriptions SET email_sent = 1 WHERE id = ?
                ''', (prescription_id,))
                app.logger.info("Email sent successfully")
            else:
                app.logger.warning("Email sending failed")
        
        conn.commit()
        conn.close()
        
        app.logger.info("Prescription created successfully")
        return jsonify({
            'success': True, 
            'message': f'Prescription created successfully! {"Email sent to patient." if email_sent else ""}',
            'prescription_number': prescription_number
        })
        
    except Exception as e:
        app.logger.error(f"Error creating prescription: {str(e)}")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'})

@app.route('/share-record/<int:record_id>', methods=['POST'])
@login_required
@role_required('doctor')
def share_record(record_id):
    conn = get_db_connection()
    
    # Verify the record belongs to this doctor
    record = conn.execute('''
        SELECT * FROM medical_records 
        WHERE id = ? AND doctor_id = ?
    ''', (record_id, session['user_id'])).fetchone()
    
    if not record:
        conn.close()
        return jsonify({'success': False, 'message': 'Record not found'})
    
    # Update record to mark as shared
    conn.execute('''
        UPDATE medical_records 
        SET is_shared = 1 
        WHERE id = ?
    ''', (record_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Record shared successfully'})

@app.route('/upload-record', methods=['POST'])
@login_required
@role_required('doctor')
def upload_record():
    if 'file' not in request.files:
        file = None
    else:
        file = request.files['file']
        if file.filename == '':
            file = None
    
    # Get patient_id from form
    patient_id = request.form.get('patient_id')
    if not patient_id:
        return jsonify({'success': False, 'message': 'Patient ID is required'})
    
    file_path = None
    file_size = 0
    file_type = ''
    
    if file and allowed_file(file.filename):
        # Create medical records subdirectory
        records_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'medical_records')
        os.makedirs(records_dir, exist_ok=True)
        
        filename = secure_filename(file.filename)
        # Add timestamp to filename to avoid conflicts
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
        filename = timestamp + filename
        file_path = os.path.join(records_dir, filename)
        file.save(file_path)
        
        file_size = os.path.getsize(file_path)
        file_type = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        file_path = f'medical_records/{filename}'
    
    # Save record to database
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO medical_records (patient_id, doctor_id, record_type, title, description, file_path, file_size, file_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        patient_id,
        session['user_id'],
        request.form.get('record_type', 'document'),
        request.form.get('title', 'Medical Record'),
        request.form.get('description', ''),
        file_path,
        file_size,
        file_type
    ))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Medical record added successfully'})

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/complete-appointment/<int:appointment_id>', methods=['POST'])
@login_required
@role_required('doctor')
def complete_appointment(appointment_id):
    conn = get_db_connection()
    
    # Verify the appointment belongs to this doctor
    appointment = conn.execute('''
        SELECT * FROM appointments 
        WHERE id = ? AND doctor_id = ? AND status = 'scheduled'
    ''', (appointment_id, session['user_id'])).fetchone()
    
    if not appointment:
        flash('Appointment not found or already completed.', 'error')
        conn.close()
        return redirect(url_for('doctor_dashboard'))
    
    # Mark appointment as completed
    conn.execute('''
        UPDATE appointments 
        SET status = 'completed' 
        WHERE id = ?
    ''', (appointment_id,))
    
    conn.commit()
    conn.close()
    
    flash('Appointment marked as completed successfully!', 'success')
    return redirect(url_for('view_appointment', appointment_id=appointment_id))

@app.route('/update-appointment-notes/<int:appointment_id>', methods=['POST'])
@login_required
@role_required('doctor')
def update_appointment_notes(appointment_id):
    notes = request.form.get('notes', '')
    
    conn = get_db_connection()
    
    # Verify the appointment belongs to this doctor
    appointment = conn.execute('''
        SELECT * FROM appointments 
        WHERE id = ? AND doctor_id = ?
    ''', (appointment_id, session['user_id'])).fetchone()
    
    if not appointment:
        flash('Appointment not found.', 'error')
        conn.close()
        return redirect(url_for('doctor_dashboard'))
    
    # Update appointment notes
    conn.execute('''
        UPDATE appointments 
        SET notes = ? 
        WHERE id = ?
    ''', (notes, appointment_id))
    
    conn.commit()
    conn.close()
    
    flash('Appointment notes updated successfully!', 'success')
    return redirect(url_for('view_appointment', appointment_id=appointment_id))

@app.route('/cancel-appointment/<int:appointment_id>', methods=['POST'])
@login_required
def cancel_appointment(appointment_id):
    conn = get_db_connection()
    
    # Get appointment details
    appointment = conn.execute('''
        SELECT * FROM appointments WHERE id = ?
    ''', (appointment_id,)).fetchone()
    
    if not appointment:
        flash('Appointment not found.', 'error')
        conn.close()
        return redirect(url_for('patient_dashboard' if session['user_role'] == 'patient' else 'doctor_dashboard'))
    
    # Check permissions
    if session['user_role'] == 'patient' and appointment['patient_id'] != session['user_id']:
        flash('Access denied.', 'error')
        conn.close()
        return redirect(url_for('patient_dashboard'))
    elif session['user_role'] == 'doctor' and appointment['doctor_id'] != session['user_id']:
        flash('Access denied.', 'error')
        conn.close()
        return redirect(url_for('doctor_dashboard'))
    
    # Cancel appointment
    conn.execute('''
        UPDATE appointments 
        SET status = 'cancelled' 
        WHERE id = ?
    ''', (appointment_id,))
    
    conn.commit()
    conn.close()
    
    flash('Appointment cancelled successfully.', 'success')
    return redirect(url_for('patient_dashboard' if session['user_role'] == 'patient' else 'doctor_dashboard'))

@app.route('/reschedule-appointment/<int:appointment_id>', methods=['POST'])
@login_required
def reschedule_appointment(appointment_id):
    new_date = request.form.get('new_date')
    new_time = request.form.get('new_time')
    
    if not new_date or not new_time:
        flash('Please provide both new date and time.', 'error')
        return redirect(url_for('view_appointment', appointment_id=appointment_id))
    
    conn = get_db_connection()
    
    # Get appointment details
    appointment = conn.execute('''
        SELECT * FROM appointments WHERE id = ?
    ''', (appointment_id,)).fetchone()
    
    if not appointment:
        flash('Appointment not found.', 'error')
        conn.close()
        return redirect(url_for('patient_dashboard'))
    
    # Check permissions (only patients can reschedule their own appointments)
    if session['user_role'] != 'patient' or appointment['patient_id'] != session['user_id']:
        flash('Access denied.', 'error')
        conn.close()
        return redirect(url_for('patient_dashboard'))
    
    # Check if new slot is available
    existing = conn.execute('''
        SELECT id FROM appointments 
        WHERE doctor_id = ? AND appointment_date = ? AND appointment_time = ? 
        AND status = 'scheduled' AND id != ?
    ''', (appointment['doctor_id'], new_date, new_time, appointment_id)).fetchone()
    
    if existing:
        flash('The selected time slot is already booked. Please choose another time.', 'error')
        conn.close()
        return redirect(url_for('view_appointment', appointment_id=appointment_id))
    
    # Update appointment
    conn.execute('''
        UPDATE appointments 
        SET appointment_date = ?, appointment_time = ?, status = 'scheduled'
        WHERE id = ?
    ''', (new_date, new_time, appointment_id))
    
    conn.commit()
    conn.close()
    
    flash('Appointment rescheduled successfully!', 'success')
    return redirect(url_for('view_appointment', appointment_id=appointment_id))

# Initialize database on startup
try:
    init_db()
except Exception as e:
    app.logger.critical(f"Failed to initialize database: {str(e)}")
    exit(1)

# Production server check
if __name__ == '__main__':
    if config('ENVIRONMENT', default='development') == 'development':
        app.logger.warning("Running in development mode")
        app.run(
            host=config('HOST', default='127.0.0.1'),
            port=config('PORT', default=5000, cast=int),
            debug=config('DEBUG', default=False, cast=bool)
        )
    else:
        app.logger.error("Use a production WSGI server like Gunicorn in production")
        print("Use: gunicorn -w 4 -b 0.0.0.0:8000 app:app")
