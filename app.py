from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime, timedelta
import logging
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Update this
app.config['MAIL_PASSWORD'] = 'your-app-password'     # Update this

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                   format='%(asctime)s %(levelname)s %(name)s %(message)s')

# Database initialization
def init_db():
    conn = sqlite3.connect('medtrak.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('patient', 'doctor')),
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            profile_picture TEXT
        )
    ''')
    
    # Doctor profiles
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS doctor_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            specialization TEXT NOT NULL,
            license_number TEXT UNIQUE NOT NULL,
            experience_years INTEGER,
            bio TEXT,
            consultation_fee REAL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Patient profiles
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS patient_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date_of_birth DATE,
            gender TEXT,
            blood_type TEXT,
            emergency_contact TEXT,
            emergency_phone TEXT,
            medical_history TEXT,
            allergies TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Appointments table
    cursor.execute('''
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
            FOREIGN KEY (patient_id) REFERENCES users (id),
            FOREIGN KEY (doctor_id) REFERENCES users (id)
        )
    ''')
    
    # Medical records table
    cursor.execute('''
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (patient_id) REFERENCES users (id),
            FOREIGN KEY (doctor_id) REFERENCES users (id),
            FOREIGN KEY (appointment_id) REFERENCES appointments (id)
        )
    ''')
    
    # Prescriptions table
    cursor.execute('''
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
            FOREIGN KEY (patient_id) REFERENCES users (id),
            FOREIGN KEY (doctor_id) REFERENCES users (id),
            FOREIGN KEY (appointment_id) REFERENCES appointments (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
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

# Helper functions
def get_db_connection():
    conn = sqlite3.connect('medtrak.db')
    conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'bmp', 'webp'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_email(to_email, subject, body, attachment_path=None):
    """Send email with optional attachment"""
    try:
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
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
        
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        text = msg.as_string()
        server.sendmail(app.config['MAIL_USERNAME'], to_email, text)
        server.quit()
        return True
    except Exception as e:
        logging.error(f"Email sending failed: {str(e)}")
        return False

def generate_prescription_number():
    """Generate unique prescription number"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    return f"RX{timestamp}"

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        phone = request.form.get('phone', '')
        
        # Validate input
        if not all([username, email, password, role, first_name, last_name]):
            flash('All required fields must be filled.', 'error')
            return render_template('register.html')
        
        conn = get_db_connection()
        
        # Check if user already exists
        existing_user = conn.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            (username, email)
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
        ''', (username, email, password_hash, role, first_name, last_name, phone))
        
        user_id = cursor.lastrowid
        
        # Create role-specific profile
        if role == 'doctor':
            specialization = request.form.get('specialization', '')
            license_number = request.form.get('license_number', '')
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
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_role'] = user['role']
            session['username'] = user['username']
            session['first_name'] = user['first_name']
            session['profile_picture'] = user['profile_picture']
            
            flash(f'Welcome back, {user["first_name"]}!', 'success')
            
            if user['role'] == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            else:
                return redirect(url_for('patient_dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
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

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=8000)
