#!/usr/bin/env python3
"""
Create upload directory structure for MedTrak application
"""

import os

def create_upload_directories():
    """Create the necessary upload directories"""
    
    base_upload_dir = 'uploads'
    subdirectories = [
        'profile_pictures',
        'medical_records',
        'prescriptions',
        'lab_results',
        'xrays',
        'reports',
        'temp'
    ]
    
    # Create base upload directory
    os.makedirs(base_upload_dir, exist_ok=True)
    print(f"Created directory: {base_upload_dir}")
    
    # Create subdirectories
    for subdir in subdirectories:
        full_path = os.path.join(base_upload_dir, subdir)
        os.makedirs(full_path, exist_ok=True)
        print(f"Created directory: {full_path}")
    
    # Create .gitkeep files to ensure directories are tracked in git
    for subdir in subdirectories:
        gitkeep_path = os.path.join(base_upload_dir, subdir, '.gitkeep')
        with open(gitkeep_path, 'w') as f:
            f.write('# This file ensures the directory is tracked by git\n')
        print(f"Created .gitkeep: {gitkeep_path}")
    
    print("\nUpload directory structure created successfully!")
    print("Directory structure:")
    print("uploads/")
    for subdir in subdirectories:
        print(f"  ├── {subdir}/")
    
    # Create a .gitignore for the uploads directory
    gitignore_path = os.path.join(base_upload_dir, '.gitignore')
    with open(gitignore_path, 'w') as f:
        f.write("""# Ignore all uploaded files except .gitkeep
*
!.gitkeep
!.gitignore
""")
    print(f"\nCreated .gitignore: {gitignore_path}")

if __name__ == "__main__":
    create_upload_directories()
