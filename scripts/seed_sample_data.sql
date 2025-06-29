-- Seed sample data for testing the MedTrak application
-- This script adds sample doctors, patients, and appointments

-- Insert sample doctors
INSERT OR IGNORE INTO users (username, email, password_hash, role, first_name, last_name, phone) VALUES
('dr_smith', 'dr.smith@medtrak.com', 'pbkdf2:sha256:260000$salt$hash', 'doctor', 'John', 'Smith', '+1-555-0101'),
('dr_johnson', 'dr.johnson@medtrak.com', 'pbkdf2:sha256:260000$salt$hash', 'doctor', 'Sarah', 'Johnson', '+1-555-0102'),
('dr_williams', 'dr.williams@medtrak.com', 'pbkdf2:sha256:260000$salt$hash', 'doctor', 'Michael', 'Williams', '+1-555-0103'),
('dr_brown', 'dr.brown@medtrak.com', 'pbkdf2:sha256:260000$salt$hash', 'doctor', 'Emily', 'Brown', '+1-555-0104'),
('dr_davis', 'dr.davis@medtrak.com', 'pbkdf2:sha256:260000$salt$hash', 'doctor', 'David', 'Davis', '+1-555-0105');

-- Insert doctor profiles
INSERT OR IGNORE INTO doctor_profiles (user_id, specialization, license_number, experience_years, bio, consultation_fee) VALUES
(1, 'Cardiology', 'MD001234', 15, 'Experienced cardiologist specializing in heart disease prevention and treatment.', 200.00),
(2, 'Pediatrics', 'MD001235', 12, 'Board-certified pediatrician with expertise in child healthcare and development.', 150.00),
(3, 'Orthopedics', 'MD001236', 18, 'Orthopedic surgeon specializing in sports injuries and joint replacement.', 250.00),
(4, 'Dermatology', 'MD001237', 10, 'Dermatologist focused on skin health, cosmetic procedures, and skin cancer prevention.', 180.00),
(5, 'Internal Medicine', 'MD001238', 20, 'Internal medicine physician with comprehensive adult healthcare experience.', 175.00);

-- Insert sample patients
INSERT OR IGNORE INTO users (username, email, password_hash, role, first_name, last_name, phone) VALUES
('patient_alice', 'alice@email.com', 'pbkdf2:sha256:260000$salt$hash', 'patient', 'Alice', 'Cooper', '+1-555-0201'),
('patient_bob', 'bob@email.com', 'pbkdf2:sha256:260000$salt$hash', 'patient', 'Bob', 'Wilson', '+1-555-0202'),
('patient_carol', 'carol@email.com', 'pbkdf2:sha256:260000$salt$hash', 'patient', 'Carol', 'Martinez', '+1-555-0203'),
('patient_david', 'david@email.com', 'pbkdf2:sha256:260000$salt$hash', 'patient', 'David', 'Anderson', '+1-555-0204'),
('patient_eve', 'eve@email.com', 'pbkdf2:sha256:260000$salt$hash', 'patient', 'Eve', 'Thompson', '+1-555-0205');

-- Insert patient profiles
INSERT OR IGNORE INTO patient_profiles (user_id, date_of_birth, gender, blood_type, emergency_contact, emergency_phone) VALUES
(6, '1985-03-15', 'female', 'A+', 'John Cooper', '+1-555-0301'),
(7, '1990-07-22', 'male', 'O-', 'Mary Wilson', '+1-555-0302'),
(8, '1978-11-08', 'female', 'B+', 'Carlos Martinez', '+1-555-0303'),
(9, '1982-05-30', 'male', 'AB+', 'Linda Anderson', '+1-555-0304'),
(10, '1995-09-12', 'female', 'O+', 'Robert Thompson', '+1-555-0305');

-- Insert sample appointments
INSERT OR IGNORE INTO appointments (patient_id, doctor_id, appointment_date, appointment_time, status, reason) VALUES
(6, 1, '2024-01-15', '09:00', 'scheduled', 'Annual cardiac checkup'),
(7, 2, '2024-01-16', '10:30', 'scheduled', 'Child vaccination'),
(8, 3, '2024-01-17', '14:00', 'scheduled', 'Knee pain consultation'),
(9, 4, '2024-01-18', '11:00', 'scheduled', 'Skin rash examination'),
(10, 5, '2024-01-19', '15:30', 'scheduled', 'General health checkup'),
(6, 2, '2024-01-10', '09:30', 'completed', 'Follow-up consultation'),
(7, 1, '2024-01-12', '16:00', 'completed', 'Heart palpitations');

-- Insert sample medical records
INSERT OR IGNORE INTO medical_records (patient_id, doctor_id, record_type, title, description) VALUES
(6, 1, 'report', 'Cardiac Assessment Report', 'Comprehensive cardiac evaluation showing normal heart function.'),
(6, 2, 'prescription', 'Blood Pressure Medication', 'Prescribed medication for mild hypertension management.'),
(7, 2, 'note', 'Vaccination Record', 'Updated vaccination schedule completed successfully.'),
(8, 3, 'diagnosis', 'Knee Injury Assessment', 'Minor ligament strain, recommended physical therapy.'),
(9, 4, 'lab_result', 'Skin Biopsy Results', 'Benign skin lesion, no further treatment required.');

-- Insert sample prescriptions
INSERT OR IGNORE INTO prescriptions (patient_id, doctor_id, medication_name, dosage, frequency, duration, instructions) VALUES
(6, 1, 'Lisinopril', '10mg', 'Once daily', '30 days', 'Take with food, monitor blood pressure'),
(7, 2, 'Amoxicillin', '500mg', 'Three times daily', '7 days', 'Complete full course even if feeling better'),
(8, 3, 'Ibuprofen', '400mg', 'As needed', '14 days', 'Take with food, maximum 3 times per day'),
(10, 5, 'Multivitamin', '1 tablet', 'Once daily', '90 days', 'Take with breakfast');

-- Insert sample notifications
INSERT OR IGNORE INTO notifications (user_id, title, message, type, related_appointment_id) VALUES
(6, 'Appointment Reminder', 'Your appointment with Dr. Smith is tomorrow at 9:00 AM', 'info', 1),
(7, 'Appointment Confirmed', 'Your appointment with Dr. Johnson has been confirmed', 'success', 2),
(8, 'Lab Results Available', 'Your recent lab results are now available in your medical records', 'info', NULL),
(9, 'Prescription Ready', 'Your prescription is ready for pickup at the pharmacy', 'success', NULL),
(10, 'Appointment Reminder', 'Your appointment with Dr. Davis is in 2 days', 'info', 5);
