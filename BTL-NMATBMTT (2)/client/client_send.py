import requests, json, base64, time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

# --- Cấu hình ---
SERVER_URL = 'http://127.0.0.1:5000'
SERVER_PUB_KEY_PATH = 'client/rsa_keys/server_public.pem'
CLIENT_PRIVATE_KEY_PATH = 'client/rsa_keys/client_private.pem'
UPLOAD_FILENAME = 'cv.pdf' # Đảm bảo tệp này tồn tại trong cùng thư mục
USERNAME = 'testuser'  # Thay thế bằng tên người dùng đã đăng ký hợp lệ
PASSWORD = 'testpassword'  # Thay thế bằng mật khẩu cho tên người dùng ở trên

# --- Tải khóa ---
try:
    server_pub_key = RSA.import_key(open(SERVER_PUB_KEY_PATH).read())
    client_private_key = RSA.import_key(open(CLIENT_PRIVATE_KEY_PATH).read())
except FileNotFoundError as e:
    print(f"Lỗi khi tải khóa RSA: {e}. Đảm bảo 'server_public.pem' và 'client_private.pem' nằm trong thư mục 'client/rsa_keys/'.")
    exit()

# --- Hàm trợ giúp ---
def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

# Tạo một đối tượng phiên để duy trì cookie
s = requests.Session()

# --- Bước 0: Đăng nhập để lấy phiên ---
print(f"Đang cố gắng đăng nhập với tên người dùng {USERNAME}...")
login_payload = {
    'username': USERNAME,
    'password': PASSWORD
}
# Sử dụng 'data' cho gửi biểu mẫu, không phải 'json'
login_response = s.post(f'{SERVER_URL}/login', data=login_payload)
# Kiểm tra xem đăng nhập có thành công không bằng cách kiểm tra các cookie hoặc chuyển hướng
if login_response.status_code == 200 and 'user_id' in s.cookies.get_dict():
    print("Đăng nhập thành công! Phiên đã được thiết lập.")
else:
    print(f"Đăng nhập thất bại. Mã trạng thái: {login_response.status_code}")
    print("Phản hồi:", login_response.text)
    exit("Yêu cầu đăng nhập để gửi tệp.")

# --- Bước 1: Handshake ---
print("Đang thực hiện handshake...")
handshake_response = s.post(f'{SERVER_URL}/handshake', json={'ip': '127.0.0.1', 'hello': 'Hello'})
print(handshake_response.json())
if handshake_response.json().get('status') != 'Ready!':
    exit('Handshake failed')

# --- Bước 2: Ký siêu dữ liệu + mã hóa khóa phiên ---
print("Đang chuẩn bị dữ liệu tệp và mã hóa...")
metadata = {'filename': UPLOAD_FILENAME, 'timestamp': str(time.time()), 'ip': '127.0.0.1'}
metadata_bytes = json.dumps(metadata).encode()

h = SHA512.new(metadata_bytes)
signature = pkcs1_15.new(client_private_key).sign(h)

session_key = get_random_bytes(32)
cipher_rsa = PKCS1_OAEP.new(server_pub_key, hashAlgo=SHA512)
enc_session_key = cipher_rsa.encrypt(session_key)

# --- Bước 3: Mã hóa tệp ---
try:
    with open(UPLOAD_FILENAME, 'rb') as f:
        file_data = f.read()
except FileNotFoundError as e:
    print(f"Lỗi: Tệp {UPLOAD_FILENAME} không tìm thấy. Vui lòng đảm bảo tệp tồn tại trong cùng thư mục với client_send.py.")
    exit()

iv = get_random_bytes(16)
cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
ciphertext = cipher_aes.encrypt(pad(file_data))

hash_hex = SHA512.new(iv + ciphertext).hexdigest()

payload = {
    'ip': '127.0.0.1', # IP này dùng để ghi nhật ký trên máy chủ, không phải để định tuyến
    'metadata': json.dumps(metadata),
    'signature': base64.b64encode(signature).decode(),
    'enc_session_key': base64.b64encode(enc_session_key).decode(),
    'iv': base64.b64encode(iv).decode(),
    'cipher': base64.b64encode(ciphertext).decode(),
    'hash': hash_hex
}

print("Đang gửi CV đến máy chủ...")
send_cv_response = s.post(f'{SERVER_URL}/send_cv', json=payload)
print(send_cv_response.json())