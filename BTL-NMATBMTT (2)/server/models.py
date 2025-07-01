from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# KHÔNG import db từ app.py nữa để tránh vòng lặp
db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class FileHistory(db.Model):
    __tablename__ = 'file_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(20), default='completed', nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)

    # Thông tin bảo mật
    is_encrypted = db.Column(db.Boolean, default=True, nullable=False)
    is_signed = db.Column(db.Boolean, default=True, nullable=False)
    hash_verified = db.Column(db.Boolean, default=True, nullable=False)
    handshake_success = db.Column(db.Boolean, default=True, nullable=False)
    encryption_type = db.Column(db.String(50), default='AES-CBC', nullable=False)
    key_exchange_type = db.Column(db.String(50), default='RSA 1024-bit OAEP + SHA-512', nullable=False)

    # Quan hệ
    user = db.relationship('User', backref=db.backref('file_histories', lazy=True))

    def __repr__(self):
        return f'<FileHistory {self.filename}>'