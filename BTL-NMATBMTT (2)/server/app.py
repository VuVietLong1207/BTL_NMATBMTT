import os
import json
import base64
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User, FileHistory
from crypto_utils import (
    decrypt_session_key,
    verify_signature,
    aes_cbc_decrypt,
    hash_sha512,
)

# Khởi tạo Flask app
app = Flask(__name__, template_folder='../client/templates', static_folder='../client/static')

# Cấu hình ứng dụng
app.config.update({
    'SQLALCHEMY_DATABASE_URI': f"sqlite:///{os.path.join(os.path.abspath(os.path.dirname(__file__)), 'users.db')}",
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SECRET_KEY': os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production'),
    'UPLOAD_FOLDER': 'server/uploads',
    'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB
    'ALLOWED_EXTENSIONS': {'pdf', 'jpg', 'jpeg', 'png'},
    'ALLOWED_IPS': {'127.0.0.1'}
})

# Khởi tạo database
db.init_app(app)

# Tạo thư mục upload nếu chưa tồn tại
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def validate_ip(client_ip):
    return client_ip in app.config['ALLOWED_IPS']

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Vui lòng đăng nhập để truy cập trang này', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    histories = FileHistory.query.filter_by(user_id=user_id).order_by(FileHistory.upload_time.desc()).limit(5).all()

    return render_template('index.html', histories=histories)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        errors = []
        if not username:
            errors.append("Tên đăng nhập là bắt buộc")
        if not email:
            errors.append("Email là bắt buộc")
        if not password:
            errors.append("Mật khẩu là bắt buộc")
        if password != confirm_password:
            errors.append("Mật khẩu không khớp")

        if errors:
            for error in errors:
                flash(error, 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Tên đăng nhập đã tồn tại', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email đã được sử dụng', 'danger')
            return redirect(url_for('register'))

        try:
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Đăng ký thành công! Vui lòng đăng nhập', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Lỗi khi đăng ký: {str(e)}', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Vui lòng điền đầy đủ thông tin', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash('Tên đăng nhập hoặc mật khẩu không đúng', 'danger')
            return redirect(url_for('login'))

        session['user_id'] = user.id
        session['username'] = user.username
        flash('Đăng nhập thành công!', 'success')
        return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/handshake', methods=['POST'])
def handshake():
    if not request.is_json:
        return jsonify({'status': 'Rejected', 'error': 'Invalid content type'}), 400

    data = request.get_json()
    client_ip = request.remote_addr

    if not validate_ip(client_ip):
        return jsonify({'status': 'Rejected', 'error': 'IP not allowed'}), 403

    if data.get('hello') != 'Hello':
        return jsonify({'status': 'Rejected', 'error': 'Invalid handshake'}), 400

    return jsonify({
        'status': 'Ready!',
        'version': '1.0',
        'ip': client_ip,
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/send_cv', methods=['POST'])
@login_required
def send_cv():
    if not request.is_json:
        return jsonify({'status': 'NACK', 'error': 'Invalid content type'}), 400

    try:
        data = request.get_json()
        client_ip = request.remote_addr
        user_id = session['user_id']

        required_fields = ['metadata', 'signature', 'enc_session_key', 'iv', 'cipher', 'hash']
        if not all(field in data for field in required_fields):
            return jsonify({'status': 'NACK', 'error': 'Missing required fields'}), 400

        metadata = data['metadata'].encode()
        signature = base64.b64decode(data['signature'])
        enc_session_key = base64.b64decode(data['enc_session_key'])
        iv = base64.b64decode(data['iv'])
        cipher = base64.b64decode(data['cipher'])
        recv_hash = data['hash']

        if not verify_signature(metadata, signature):
            return jsonify({'status': 'NACK', 'error': 'Invalid signature'}), 401

        session_key = decrypt_session_key(enc_session_key)
        current_hash = hash_sha512(iv + cipher)

        if current_hash != recv_hash:
            return jsonify({'status': 'NACK', 'error': 'Hash verification failed'}), 401

        plaintext = aes_cbc_decrypt(cipher, iv, session_key)
        file_info = json.loads(metadata)
        safe_filename = secure_filename(file_info['filename'])
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)

        with open(file_path, 'wb') as f:
            f.write(plaintext)

        ip_verified = validate_ip(client_ip)

        new_history = FileHistory(
            user_id=user_id,
            filename=safe_filename,
            file_size=len(plaintext),
            ip_address=client_ip,
            status='completed',
            is_encrypted=True,
            is_signed=True,
            hash_verified=True,
            handshake_success=True,
            ip_verified=ip_verified,
            encryption_type='AES-256-CBC',
            key_exchange_type='RSA 1024-bit OAEP + SHA-512'
        )

        db.session.add(new_history)
        db.session.commit()

        return jsonify({'status': 'ACK', 'filename': safe_filename})

    except Exception as e:
        app.logger.error(f"Error processing file: {str(e)}", exc_info=True)
        return jsonify({'status': 'NACK', 'error': 'Internal server error'}), 500

@app.route('/history')
@login_required
def history():
    user_id = session.get('user_id')
    histories = FileHistory.query.filter_by(user_id=user_id).order_by(FileHistory.upload_time.desc()).all()
    return render_template('history.html', histories=histories)

# Khởi chạy ứng dụng
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
