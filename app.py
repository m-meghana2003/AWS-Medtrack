from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime, timedelta
import logging
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

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
            session['profile_picture'] = user['profile_picture']  # Add this line
            
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
    
    conn.close()
    
    return render_template('patient_dashboard.html', 
                         appointments=appointments, 
                         records=records)

@app.route('/doctor/dashboard')
@login_required
@role_required('doctor')
def doctor_dashboard():
    conn = get_db_connection()
    
    # Get today's appointments
    today = datetime.now().date()
    appointments = conn.execute('''
        SELECT a.*, u.first_name, u.last_name, u.phone
        FROM appointments a
        JOIN users u ON a.patient_id = u.id
        WHERE a.doctor_id = ? AND a.appointment_date = ? AND a.status = 'scheduled'
        ORDER BY a.appointment_time
    ''', (session['user_id'], today)).fetchall()
    
    # Get upcoming appointments
    upcoming = conn.execute('''
        SELECT a.*, u.first_name, u.last_name
        FROM appointments a
        JOIN users u ON a.patient_id = u.id
        WHERE a.doctor_id = ? AND a.appointment_date > ? AND a.status = 'scheduled'
        ORDER BY a.appointment_date, a.appointment_time
        LIMIT 10
    ''', (session['user_id'], today)).fetchall()
    
    conn.close()
    
    return render_template('doctor_dashboard.html', 
                         today_appointments=appointments,
                         upcoming_appointments=upcoming)

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
@role_required('doctor')  # Change this to require doctor role
def upload_record():
    if 'file' not in request.files:
        # Allow records without files (text-only records)
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

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=8000)
