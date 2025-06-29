#!/usr/bin/env python3
"""
Admin setup script for MedTrak application
Creates an admin user and sets up initial system configuration
"""

import sqlite3
import sys
from werkzeug.security import generate_password_hash
from datetime import datetime

def create_admin_user():
    """Create an admin user for system management"""
    
    # Admin user details
    admin_data = {
        'username': 'admin',
        'email': 'admin@medtrak.com',
        'password': 'admin123',  # Change this in production!
        'first_name': 'System',
        'last_name': 'Administrator',
        'phone': '+1-555-0000'
    }
    
    try:
        # Connect to database
        conn = sqlite3.connect('medtrak.db')
        cursor = conn.cursor()
        
        # Check if admin already exists
        existing_admin = cursor.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            (admin_data['username'], admin_data['email'])
        ).fetchone()
        
        if existing_admin:
            print("Admin user already exists!")
            return
        
        # Hash password
        password_hash = generate_password_hash(admin_data['password'])
        
        # Insert admin user
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role, first_name, last_name, phone)
            VALUES (?, ?, ?, 'doctor', ?, ?, ?)
        ''', (
            admin_data['username'],
            admin_data['email'],
            password_hash,
            admin_data['first_name'],
            admin_data['last_name'],
            admin_data['phone']
        ))
        
        admin_id = cursor.lastrowid
        
        # Create admin doctor profile
        cursor.execute('''
            INSERT INTO doctor_profiles (user_id, specialization, license_number, bio)
            VALUES (?, ?, ?, ?)
        ''', (
            admin_id,
            'Administration',
            'ADMIN001',
            'System administrator with full access to MedTrak platform.'
        ))
        
        conn.commit()
        conn.close()
        
        print("Admin user created successfully!")
        print(f"Username: {admin_data['username']}")
        print(f"Password: {admin_data['password']}")
        print("Please change the default password after first login.")
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error creating admin user: {e}")
        sys.exit(1)

def setup_system_settings():
    """Set up initial system configuration"""
    
    try:
        conn = sqlite3.connect('medtrak.db')
        cursor = conn.cursor()
        
        # Create system settings table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT UNIQUE NOT NULL,
                setting_value TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Default system settings
        default_settings = [
            ('app_name', 'MedTrak', 'Application name'),
            ('app_version', '1.0.0', 'Application version'),
            ('max_file_size', '16777216', 'Maximum file upload size in bytes (16MB)'),
            ('allowed_file_types', 'pdf,doc,docx,jpg,jpeg,png,gif,txt', 'Allowed file extensions'),
            ('appointment_duration', '30', 'Default appointment duration in minutes'),
            ('booking_advance_days', '30', 'Maximum days in advance for booking'),
            ('cancellation_hours', '24', 'Minimum hours before appointment for cancellation'),
            ('notification_enabled', '1', 'Enable system notifications'),
            ('email_notifications', '1', 'Enable email notifications'),
            ('sms_notifications', '0', 'Enable SMS notifications'),
            ('backup_enabled', '1', 'Enable automatic database backups'),
            ('maintenance_mode', '0', 'System maintenance mode')
        ]
        
        for key, value, description in default_settings:
            cursor.execute('''
                INSERT OR IGNORE INTO system_settings (setting_key, setting_value, description)
                VALUES (?, ?, ?)
            ''', (key, value, description))
        
        conn.commit()
        conn.close()
        
        print("System settings configured successfully!")
        
    except sqlite3.Error as e:
        print(f"Database error setting up system settings: {e}")
        sys.exit(1)

def create_sample_specializations():
    """Create a list of common medical specializations"""
    
    specializations = [
        'Cardiology', 'Dermatology', 'Endocrinology', 'Gastroenterology',
        'Hematology', 'Infectious Disease', 'Internal Medicine', 'Nephrology',
        'Neurology', 'Oncology', 'Orthopedics', 'Pediatrics', 'Psychiatry',
        'Pulmonology', 'Radiology', 'Rheumatology', 'Surgery', 'Urology',
        'Obstetrics and Gynecology', 'Ophthalmology', 'Otolaryngology',
        'Anesthesiology', 'Emergency Medicine', 'Family Medicine',
        'Physical Medicine', 'Pathology', 'Plastic Surgery'
    ]
    
    try:
        conn = sqlite3.connect('medtrak.db')
        cursor = conn.cursor()
        
        # Create specializations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS specializations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert specializations
        for spec in specializations:
            cursor.execute('''
                INSERT OR IGNORE INTO specializations (name)
                VALUES (?)
            ''', (spec,))
        
        conn.commit()
        conn.close()
        
        print(f"Added {len(specializations)} medical specializations!")
        
    except sqlite3.Error as e:
        print(f"Database error creating specializations: {e}")
        sys.exit(1)

def main():
    """Main setup function"""
    print("Setting up MedTrak Admin...")
    print("=" * 40)
    
    # Create admin user
    create_admin_user()
    print()
    
    # Setup system settings
    setup_system_settings()
    print()
    
    # Create specializations
    create_sample_specializations()
    print()
    
    print("Setup completed successfully!")
    print("You can now run the application with: python app.py")

if __name__ == "__main__":
    main()
