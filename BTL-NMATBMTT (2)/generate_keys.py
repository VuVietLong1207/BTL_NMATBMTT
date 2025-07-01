from Crypto.PublicKey import RSA
import os, shutil

os.makedirs('server/rsa_keys', exist_ok=True)
os.makedirs('client/rsa_keys', exist_ok=True)

# Server key
server_key = RSA.generate(1024)
with open('server/rsa_keys/server_private.pem', 'wb') as f:
    f.write(server_key.export_key())
with open('server/rsa_keys/server_public.pem', 'wb') as f:
    f.write(server_key.publickey().export_key())

# Client key
client_key = RSA.generate(1024)
with open('client/rsa_keys/client_private.pem', 'wb') as f:
    f.write(client_key.export_key())
with open('client/rsa_keys/client_public.pem', 'wb') as f:
    f.write(client_key.publickey().export_key())

# Trao public key
shutil.copy('client/rsa_keys/client_public.pem', 'server/rsa_keys/client_public.pem')
shutil.copy('server/rsa_keys/server_public.pem', 'client/rsa_keys/server_public.pem')

print('✅ Đã tạo xong và trao đổi public key.')
