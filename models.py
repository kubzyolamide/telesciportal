from datetime import datetime, timezone

def init_models(db):
    """Binds relational structures to the local Relational Storage engine."""
    
    global User, Material, Course, Download, ActivityLog

    class User(db.Model):
        __tablename__ = 'users'
        id = db.Column(db.Integer, primary_key=True)
        full_name = db.Column(db.String(150), nullable=False)
        email = db.Column(db.String(150), unique=True, nullable=False)
        institutional_id = db.Column(db.String(50), unique=True, nullable=False)
        password_hash = db.Column(db.String(256), nullable=False)
        role = db.Column(db.String(20), nullable=False)  # 'Admin', 'Lecturer', 'Student', 'Rep'
        department = db.Column(db.String(100), default='Telecommunication Science')
        level = db.Column(db.String(20), nullable=True)  
        
        password_status = db.Column(db.String(20), default='Default')  # 'Default' or 'Changed'
        assigned_course_code = db.Column(db.String(20), nullable=True) 
        
        is_verified = db.Column(db.Boolean, default=True)
        created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
        
        materials_uploaded = db.relationship('Material', backref='uploader', lazy=True)
        downloads_made = db.relationship('Download', backref='user', lazy=True)
        logs = db.relationship('ActivityLog', backref='user', lazy=True)

    class Material(db.Model):
        __tablename__ = 'materials'
        id = db.Column(db.Integer, primary_key=True)
        title = db.Column(db.String(200), nullable=False)
        description = db.Column(db.Text, nullable=True)
        course_code = db.Column(db.String(20), nullable=False)
        course_title = db.Column(db.String(150), nullable=False)
        level = db.Column(db.String(20), nullable=False)          
        semester = db.Column(db.String(30), nullable=False)       
        academic_year = db.Column(db.String(20), nullable=False)   
        material_type = db.Column(db.String(30), nullable=False)   
        file_path = db.Column(db.String(255), nullable=False)
        file_hash = db.Column(db.String(64), nullable=True)
        upload_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
        uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        
        downloads = db.relationship('Download', backref='material', lazy=True)

    class Course(db.Model):
        __tablename__ = 'courses'
        id = db.Column(db.Integer, primary_key=True)
        course_code = db.Column(db.String(20), unique=True, nullable=False)
        course_title = db.Column(db.String(150), nullable=False)
        level = db.Column(db.String(20), nullable=False)
        semester = db.Column(db.String(30), default='Harmattan Semester')
        department = db.Column(db.String(100), default='Telecommunication Science')

    class Download(db.Model):
        __tablename__ = 'downloads'
        id = db.Column(db.Integer, primary_key=True)
        download_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
        material_id = db.Column(db.Integer, db.ForeignKey('materials.id'), nullable=False)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    class ActivityLog(db.Model):
        __tablename__ = 'activity_log'
        id = db.Column(db.Integer, primary_key=True)
        action = db.Column(db.String(255), nullable=False)
        timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    return User, Material, Course, Download, ActivityLog