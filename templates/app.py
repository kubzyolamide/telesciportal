from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import re
import uuid
import hashlib
import io
import csv
from datetime import datetime, timezone

base_dir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__, template_folder=os.path.join(base_dir, 'templates'))

app.config['SECRET_KEY'] = 'telesci_dev_secret_key_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(base_dir, 'telesci.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = os.path.join(base_dir, 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'pptx', 'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

db = SQLAlchemy(app)

from models import init_models
User, Material, Course, Download, ActivityLog = init_models(db)

# ---------------------------------------------------------------------------
# Password policy helpers
#   1. Login credentials (both identifier and password) are case-insensitive
#   2. A new password may never equal the account's current/default password
#   3. Minimum complexity: 8+ chars with a letter, a number, and a special
#      character (10+ chars with 2 numbers for Lecturer accounts, given
#      their upload privileges)
# ---------------------------------------------------------------------------
SPECIAL_CHARS = r"""!@#$%^&*(),.?":{}|<>_\-+=/\\;'\[\]`~"""


def normalize_credential(value):
    """Case-insensitive normalization applied identically to login
    identifiers and passwords, both when hashing and when verifying."""
    return (value or '').strip().lower()


def validate_password_complexity(password, role='Student'):
    """Returns (is_valid, error_message). Enforces the minimum-complexity
    rule, with a stricter floor for Lecturer accounts."""
    password = password or ''
    min_length = 10 if role == 'Lecturer' else 8

    if len(password) < min_length:
        return False, f"Password must be at least {min_length} characters long."
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number."
    if not re.search(f'[{SPECIAL_CHARS}]', password):
        return False, "Password must contain at least one special character."
    if role == 'Lecturer' and len(re.findall(r'[0-9]', password)) < 2:
        return False, "Lecturer passwords must contain at least two numbers."

    return True, ""


def log_system_action(action_text, user_id=None):
    try:
        new_log = ActivityLog(action=action_text, user_id=user_id)
        db.session.add(new_log)
        db.session.commit()
    except Exception:
        db.session.rollback()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_file_md5(file_storage):
    md5_hash = hashlib.md5()
    file_storage.seek(0)
    for chunk in iter(lambda: file_storage.read(4096), b""):
        md5_hash.update(chunk)
    file_storage.seek(0) 
    return md5_hash.hexdigest()

def extract_default_password(full_name):
    parts = full_name.strip().split()
    if parts:
        return parts[0].strip().capitalize()
    return "TeleSci2026"

# End-of-session level promotion map. 400 Level has no entry on purpose —
# final-year students are not auto-promoted further; the admin removes or
# reassigns them manually once they graduate.
LEVEL_PROMOTION_MAP = {
    '100 Level': '200 Level',
    '200 Level': '300 Level',
    '300 Level': '400 Level',
}

@app.before_request
def check_forced_password_status():
    allowed_routes = ['login', 'logout', 'static', 'force_reset', 'serve_manifest', 'serve_sw', 'init_admin']
    if request.endpoint in allowed_routes or not request.endpoint:
        return
        
    if 'user_id' in session:
        current_user = User.query.get(session['user_id'])
        if current_user and current_user.password_status == 'Default' and current_user.role != 'Admin':
            return redirect(url_for('force_reset'))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/force-reset-password', methods=['GET', 'POST'])
def force_reset():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if new_password != confirm_password:
            flash('Error: Passwords do not match.')
            return redirect(url_for('force_reset'))

        user = User.query.get(session['user_id'])

        # Rule 3: minimum complexity (stricter for Lecturer accounts)
        is_valid, error_msg = validate_password_complexity(new_password, user.role)
        if not is_valid:
            flash(f'Error: {error_msg}')
            return redirect(url_for('force_reset'))

        # Rule 2: new password must not equal the current/default password
        normalized_new = normalize_credential(new_password)
        if check_password_hash(user.password_hash, normalized_new):
            flash('Error: New password must be different from your current/default password.')
            return redirect(url_for('force_reset'))

        # Rule 1: passwords are stored/verified case-insensitively
        user.password_hash = generate_password_hash(normalized_new, method='pbkdf2:sha256')
        user.password_status = 'Changed'
        db.session.commit()
        
        log_system_action(f"User {user.full_name} updated their default password.", user.id)
        flash('Password updated successfully!')
        if user.role in ['Student', 'Rep']:
            return redirect(url_for('student_dashboard'))
        elif user.role == 'Lecturer':
            return redirect(url_for('lecturer_dashboard'))
            
    return render_template('force_reset.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Rule 1: both the login identifier and the password are matched
        # case-insensitively.
        login_input = normalize_credential(request.form.get('login_input', ''))
        password = normalize_credential(request.form.get('password', ''))

        user = User.query.filter(
            (db.func.lower(User.email) == login_input) |
            (db.func.lower(User.institutional_id) == login_input)
        ).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid login details.')
            return redirect(url_for('login'))
            
        session['user_id'] = user.id
        session['user_name'] = user.full_name
        session['user_role'] = user.role
        session['user_level'] = user.level or '400 Level'
        session['user_title'] = user.title or ''
            
        log_system_action(f"User logged in: {user.full_name} ({user.role})", user.id)
        if user.role in ['Student', 'Rep']:
            return redirect(url_for('student_dashboard'))
        elif user.role == 'Lecturer':
            return redirect(url_for('lecturer_dashboard'))
        elif user.role == 'Admin':
            return redirect(url_for('admin_dashboard'))
            
    return render_template('login.html')

@app.route('/dashboard/student', methods=['GET', 'POST'])
def student_dashboard():
    if 'user_id' not in session or session.get('user_role') not in ['Student', 'Rep']:
        return redirect(url_for('login'))
        
    level_hierarchy = {'100 Level': 1, '200 Level': 2, '300 Level': 3, '400 Level': 4}
    student_rank = level_hierarchy.get(session.get('user_level', '400 Level'), 4)
    
    if request.method == 'POST' and session.get('user_role') == 'Rep':
        title = request.form.get('title')
        ccode = request.form.get('course_code').strip().upper()
        clevel = request.form.get('level')
        csemester = request.form.get('semester')
        
        course_ref = Course.query.filter_by(course_code=ccode).first()
        ctitle = course_ref.course_title if course_ref else "Departmental Materials"
        
        file = request.files['file']
        if file and allowed_file(file.filename):
            computed_md5 = generate_file_md5(file)
            secure_storage_name = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_storage_name))
            
            new_mat = Material(
                title=title, description="Uploaded by Student Rep", course_code=ccode,
                course_title=ctitle, level=clevel, semester=csemester,
                academic_year="2025/2026", material_type="Past Question",
                file_path=secure_storage_name, file_hash=computed_md5, uploaded_by=session['user_id']
            )
            db.session.add(new_mat)
            db.session.commit()
            log_system_action(f"Course Rep uploaded Past Question: '{title}' for {ccode}.", session['user_id'])
            flash('Past Question uploaded successfully!')
            return redirect(url_for('student_dashboard'))

    search_query = request.args.get('search', '').strip()
    query = Material.query
    if search_query:
        query = query.filter((Material.title.like(f"%{search_query}%")) | (Material.course_code.like(f"%{search_query}%")))
        
    all_materials = query.order_by(Material.upload_date.desc()).all()
    authorized_materials = [m for m in all_materials if level_hierarchy.get(m.level, 1) <= student_rank]

    # Attach a display-ready "Dr. Adeniran"-style uploader name to each
    # material, without needing a model relationship — just a lookup dict
    # built from the small set of uploader ids actually on this page.
    uploader_ids = {m.uploaded_by for m in authorized_materials if m.uploaded_by}
    uploader_map = {u.id: u for u in User.query.filter(User.id.in_(uploader_ids)).all()} if uploader_ids else {}
    for m in authorized_materials:
        uploader = uploader_map.get(m.uploaded_by)
        if uploader:
            m.uploader_display = f"{uploader.title + ' ' if uploader.title else ''}{uploader.full_name}"
        else:
            m.uploader_display = "TeleSci Admin"

    courses = Course.query.all()
    return render_template('student.html', materials=authorized_materials, search_query=search_query, student_rank=student_rank, courses=courses)

@app.route('/dashboard/lecturer', methods=['GET', 'POST'])
def lecturer_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'Lecturer':
        return redirect(url_for('login'))
        
    current_user = User.query.get(session['user_id'])
    assigned_code = current_user.assigned_course_code
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        material_type = request.form.get('material_type')
        academic_year = request.form.get('academic_year')
        
        course_info = request.form.get('selected_course_info', '').split('|')
        if len(course_info) < 2 or course_info[0] != assigned_code:
            flash('Error: You can only upload files for your assigned course!')
            return redirect(url_for('lecturer_dashboard'))
            
        file = request.files['file']
        if file and allowed_file(file.filename):
            computed_md5 = generate_file_md5(file)
            secure_storage_name = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_storage_name))
            
            new_material = Material(
                title=title, description=description, course_code=course_info[0],
                course_title=course_info[1], level=course_info[2], semester=course_info[3],
                academic_year=academic_year, material_type=material_type,
                file_path=secure_storage_name, file_hash=computed_md5, uploaded_by=session['user_id']
            )
            db.session.add(new_material)
            db.session.commit()
            log_system_action(f"Lecturer uploaded material: '{title}' for {assigned_code}.", current_user.id)
            flash('Material uploaded successfully!')
            return redirect(url_for('lecturer_dashboard'))
            
    my_materials = Material.query.filter_by(course_code=assigned_code).order_by(Material.upload_date.desc()).all() if assigned_code else []
    my_course_metadata = Course.query.filter_by(course_code=assigned_code).first()
    
    # FIXED: Grabbing dynamic download statistics for this lecturer's specific files
    material_ids = [m.id for m in my_materials]
    download_stats = []
    if material_ids:
        downloads = db.session.query(Download.material_id, db.func.count(Download.id)).filter(Download.material_id.in_(material_ids)).group_by(Download.material_id).all()
        download_map = dict(downloads)
        for m in my_materials:
            download_stats.append({
                'title': m.title,
                'type': m.material_type,
                'count': download_map.get(m.id, 0),
                'date': m.upload_date.strftime('%Y-%m-%d')
            })
            
    return render_template('lecturer.html', uploads=my_materials, assigned_course=my_course_metadata, download_stats=download_stats)

@app.route('/dashboard/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'Admin':
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        action_type = request.form.get('action_type')
        
        if action_type == 'provision_user':
            r_name = request.form.get('u_name')
            r_email = request.form.get('u_email')
            r_id = request.form.get('u_id')
            r_role = request.form.get('u_role')
            r_level = request.form.get('u_level')
            r_course = request.form.get('u_course')
            r_title = request.form.get('u_title', '').strip()
            
            generated_pass = extract_default_password(r_name)
            hashed_pass = generate_password_hash(normalize_credential(generated_pass), method='pbkdf2:sha256')
            
            if not User.query.filter((User.email == r_email) | (User.institutional_id == r_id)).first():
                created_user = User(
                    full_name=r_name, email=r_email, password_hash=hashed_pass,
                    role=r_role, institutional_id=r_id, is_verified=True,
                    level=r_level if r_role in ['Student', 'Rep'] else '400 Level',
                    password_status='Default', assigned_course_code=r_course if r_role == 'Lecturer' else None,
                    title=r_title if r_role == 'Lecturer' and r_title else None
                )
                db.session.add(created_user)
                db.session.commit()
                log_system_action(f"Admin created account for {r_name} ({r_role}). Default Password: '{generated_pass}'", session['user_id'])
                flash(f'Account created for {r_name}! Default Password is: "{generated_pass}"')
            else:
                flash('User already exists.')
            
        elif action_type == 'bulk_csv':
            if 'csv_file' not in request.files:
                return redirect(url_for('admin_dashboard'))
            file = request.files['csv_file']
            if file and file.filename.endswith('.csv'):
                stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
                csv_input = csv.reader(stream)
                next(csv_input, None)
                
                count = 0
                for row in csv_input:
                    if len(row) < 5:
                        continue
                    f_name, email, inst_id, role, meta_val = [x.strip() for x in row[:5]]
                    csv_title = row[5].strip() if len(row) > 5 else ''
                    
                    if not User.query.filter((User.email == email) | (User.institutional_id == inst_id)).first():
                        generated_pass = extract_default_password(f_name)
                        hashed_pass = generate_password_hash(normalize_credential(generated_pass), method='pbkdf2:sha256')
                        
                        u = User(
                            full_name=f_name, email=email, institutional_id=inst_id,
                            role=role, password_hash=hashed_pass, is_verified=True,
                            password_status='Default',
                            level=meta_val if role in ['Student', 'Rep'] else '400 Level',
                            assigned_course_code=meta_val if role == 'Lecturer' else None,
                            title=csv_title if role == 'Lecturer' and csv_title else None
                        )
                        db.session.add(u)
                        count += 1
                db.session.commit()
                log_system_action(f"Admin batch imported {count} user accounts via CSV file.", session['user_id'])
                flash(f'Successfully imported {count} accounts from CSV file!')

        elif action_type == 'admin_upload':
            title = request.form.get('title')
            ccode = request.form.get('course_code').strip().upper()
            clevel = request.form.get('level')
            csemester = request.form.get('semester')
            mtype = request.form.get('material_type')
            
            course_ref = Course.query.filter_by(course_code=ccode).first()
            ctitle = course_ref.course_title if course_ref else "General Material"
            
            file = request.files['file']
            if file and allowed_file(file.filename):
                computed_md5 = generate_file_md5(file)
                secure_storage_name = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_storage_name))
                
                new_mat = Material(
                    title=title, description="Uploaded by Admin", course_code=ccode,
                    course_title=ctitle, level=clevel, semester=csemester,
                    academic_year="2025/2026", material_type=mtype,
                    file_path=secure_storage_name, file_hash=computed_md5, uploaded_by=session['user_id']
                )
                db.session.add(new_mat)
                db.session.commit()
                log_system_action(f"Admin uploaded material file: '{title}' for course {ccode}.", session['user_id'])
                flash('Material uploaded successfully!')
                
        elif action_type == 'create_course':
            ccode = request.form.get('course_code').strip().upper()
            ctitle = request.form.get('course_title').strip()
            clevel = request.form.get('level')
            csem = request.form.get('semester')
            if not Course.query.filter_by(course_code=ccode).first():
                db.session.add(Course(course_code=ccode, course_title=ctitle, level=clevel, semester=csem))
                db.session.commit()
                log_system_action(f"Admin added new course: {ccode} - {ctitle}.", session['user_id'])
                flash('Course added successfully!')
        return redirect(url_for('admin_dashboard'))
        
    return render_template(
        'admin.html', 
        users=User.query.filter(User.role != 'Admin').order_by(User.full_name.asc()).all(),
        courses=Course.query.order_by(Course.course_code.asc()).all(),
        logs=ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(50).all(),
        students_count=User.query.filter((User.role == 'Student') | (User.role == 'Rep')).count(), 
        lecturers_count=User.query.filter_by(role='Lecturer').count(),
        resources_count=Material.query.count(), 
        downloads_count=Download.query.count()
    )

@app.route('/admin/promote-levels', methods=['POST'])
def admin_promote_levels():
    if 'user_id' not in session or session.get('user_role') != 'Admin':
        return redirect(url_for('login'))

    admin_user = User.query.get(session['user_id'])
    confirm_password = normalize_credential(request.form.get('admin_password', ''))

    # Require the admin's own password before running a bulk, hard-to-undo
    # change, so this can't be triggered by an accidental click.
    if not check_password_hash(admin_user.password_hash, confirm_password):
        flash('Error: Incorrect admin password. Level promotion was NOT performed.')
        return redirect(url_for('admin_dashboard'))

    students = User.query.filter(User.role.in_(['Student', 'Rep'])).all()
    promoted_count = 0
    graduating_count = 0

    for student in students:
        next_level = LEVEL_PROMOTION_MAP.get(student.level)
        if next_level:
            student.level = next_level
            promoted_count += 1
        elif student.level == '400 Level':
            graduating_count += 1

    db.session.commit()
    log_system_action(
        f"Admin {admin_user.full_name} ran end-of-session level promotion: "
        f"{promoted_count} student(s) promoted, {graduating_count} at 400 Level left unchanged.",
        admin_user.id
    )
    flash(f'Level promotion complete: {promoted_count} student(s) promoted. '
          f'{graduating_count} student(s) already at 400 Level were left unchanged.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset-user-password/<int:user_id>', methods=['POST'])
def admin_reset_password(user_id):
    if 'user_id' not in session or session.get('user_role') != 'Admin':
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    generated_pass = extract_default_password(user.full_name)
    user.password_hash = generate_password_hash(normalize_credential(generated_pass), method='pbkdf2:sha256')
    user.password_status = 'Default'
    db.session.commit()
    log_system_action(f"Admin reset password for user {user.full_name} back to default.", session['user_id'])
    flash(f"Password reset completed! The new default password is: {generated_pass}")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if 'user_id' not in session or session.get('user_role') != 'Admin':
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    name_cached = user.full_name
    db.session.delete(user)
    db.session.commit()
    log_system_action(f"Admin deleted user account: {name_cached}.", session['user_id'])
    flash('User removed successfully.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete-course/<int:course_id>', methods=['POST'])
def admin_delete_course(course_id):
    if 'user_id' not in session or session.get('user_role') != 'Admin':
        return redirect(url_for('login'))
    course = Course.query.get_or_404(course_id)
    code_cached = course.course_code
    db.session.delete(course)
    db.session.commit()
    log_system_action(f"Admin deleted course track: {code_cached}.", session['user_id'])
    flash(f'Course {code_cached} removed successfully.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/download-backup')
def admin_download_backup():
    if 'user_id' not in session or session.get('user_role') != 'Admin':
        return redirect(url_for('login'))
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['User ID', 'Full Name', 'Email', 'ID Number', 'Role', 'Password Status'])
    for u in User.query.all():
        cw.writerow([u.id, u.full_name, u.email, u.institutional_id, u.role, u.password_status])
    log_system_action("Admin exported system user directory to CSV file backup.", session['user_id'])
    output = Response(si.getvalue(), mimetype='text/csv')
    output.headers["Content-Disposition"] = "attachment; filename=telesci_system_backup.csv"
    return output

@app.route('/download/<filename>')
def download_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    mat = Material.query.filter_by(file_path=filename).first()
    if mat:
        db.session.add(Download(material_id=mat.id, user_id=session['user_id']))
        db.session.commit()
        log_system_action(f"File downloaded by student: {mat.title}.", session['user_id'])
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

@app.route('/init-admin')
def init_admin():
    try:
        db.create_all()
        admin_user = User.query.filter_by(role='Admin').first()
        if not admin_user:
            master_admin = User(
                full_name='System Administrator', email='admin@telesci.edu',
                password_hash=generate_password_hash(normalize_credential('admin123'), method='pbkdf2:sha256'),
                role='Admin', institutional_id='ADMIN-001', is_verified=True, level='400 Level',
                password_status='Changed'
            )
            db.session.add(master_admin)
            db.session.commit()
        flash('Local SQLite database structure verified successfully!')
    except Exception as e:
        print(e)
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
