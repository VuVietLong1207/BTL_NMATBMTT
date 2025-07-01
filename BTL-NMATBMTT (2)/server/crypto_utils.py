from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import base64
import logging
import time  # Thêm dòng này để sử dụng time.time()
import json  # Thêm dòng này để sử dụng json.dumps()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Key management
def load_key(key_path, key_type='private'):
    """Load RSA key from file with error handling"""
    try:
        with open(key_path, 'rb') as f:
            key_data = f.read()
            if key_type == 'private':
                return RSA.import_key(key_data)
            elif key_type == 'public':
                return RSA.import_key(key_data)
            else:
                raise ValueError("Invalid key type specified")
    except Exception as e:
        logger.error(f"Error loading {key_type} key from {key_path}: {str(e)}")
        raise

# Load keys with error handling
try:
    server_private_key = load_key('server/rsa_keys/server_private.pem', 'private')
    client_public_key = load_key('server/rsa_keys/client_public.pem', 'public')
except Exception as e:
    logger.critical("Failed to load cryptographic keys. Server cannot start.")
    raise

# Encryption functions
def generate_aes_key(key_size=32):
    """Generate a random AES key (256-bit by default)"""
    return get_random_bytes(key_size)

def generate_iv():
    """Generate a random initialization vector for AES-CBC"""
    return get_random_bytes(AES.block_size)

def encrypt_aes_cbc(plaintext, key, iv=None):
    """
    Encrypt data using AES-CBC mode
    Returns: (iv, ciphertext)
    """
    try:
        if iv is None:
            iv = generate_iv()
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return iv, ciphertext
    except Exception as e:
        logger.error(f"AES encryption failed: {str(e)}")
        raise

def decrypt_session_key(enc_session_key):
    """Decrypt the session key using server's private RSA key"""
    try:
        cipher_rsa = PKCS1_OAEP.new(server_private_key, hashAlgo=SHA512)
        return cipher_rsa.decrypt(enc_session_key)
    except Exception as e:
        logger.error(f"Session key decryption failed: {str(e)}")
        raise

def aes_cbc_decrypt(ciphertext, iv, session_key):
    """Decrypt data using AES-CBC mode"""
    try:
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        return unpad(decrypted_data, AES.block_size)
    except Exception as e:
        logger.error(f"AES decryption failed: {str(e)}")
        raise

# Signature functions
def sign_data(data, private_key):
    """Sign data with RSA private key"""
    try:
        h = SHA512.new(data)
        signature = pkcs1_15.new(private_key).sign(h)
        return signature
    except Exception as e:
        logger.error(f"Signing failed: {str(e)}")
        raise

def verify_signature(metadata_bytes, signature):
    """Verify signature with client's public RSA key"""
    try:
        h = SHA512.new(metadata_bytes)
        pkcs1_15.new(client_public_key).verify(h, signature)
        return True
    except (ValueError, TypeError) as e:
        logger.warning(f"Signature verification failed: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Signature verification error: {str(e)}")
        raise

# Hashing
def hash_sha512(data_bytes):
    """Generate SHA-512 hash of data"""
    try:
        return SHA512.new(data_bytes).hexdigest()
    except Exception as e:
        logger.error(f"Hashing failed: {str(e)}")
        raise

# Key exchange functions
def encrypt_rsa(plaintext, public_key):
    """Encrypt data with RSA public key"""
    try:
        cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA512)
        return cipher_rsa.encrypt(plaintext)
    except Exception as e:
        logger.error(f"RSA encryption failed: {str(e)}")
        raise

# Utility functions
def generate_metadata(filename, file_size, file_hash):
    """Generate standardized metadata dictionary"""
    return {
        'filename': filename,
        'size': file_size,
        'hash': file_hash,
        'timestamp': int(time.time()),  # Đã thêm dấu ngoặc đóng
        'version': '1.0',  # Đã thêm dấu phẩy
    }

def serialize_metadata(metadata):
    """Serialize metadata to JSON bytes"""
    return json.dumps(metadata, sort_keys=True).encode('utf-8')

if __name__ == '__main__':
    # Test the crypto functions
    test_data = b"Test data for cryptographic operations"
    print("Original data:", test_data)
    
    # Test AES encryption
    aes_key = generate_aes_key()
    iv, ciphertext = encrypt_aes_cbc(test_data, aes_key)
    print("AES encrypted:", base64.b64encode(ciphertext).decode()[:50] + "...")
    
    # Test RSA encryption
    rsa_encrypted = encrypt_rsa(aes_key, client_public_key)
    print("RSA encrypted key:", base64.b64encode(rsa_encrypted).decode()[:50] + "...")
    
    # Test hashing
    data_hash = hash_sha512(test_data)
    print("SHA-512 hash:", data_hash[:32] + "...")