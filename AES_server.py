# -*- coding: utf-8 -*-
"""
Created on Wed Feb 25 23:05:15 2026

@author: sidra
"""
import socket
from Crypto.Cipher import AES
import base64
KEY = b'12345678901234567890123456789012'    # 32 bytes for AES
IV = b'1234567890123456'                     # 16 bytes IV

def decrypt_message(enc_msg):
    encrypted_data = base64.b64decode(enc_msg)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted = cipher.decrypt(encrypted_data)
    return decrypted.decode('utf-8')  # No padding removal
# Create TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('Localhost', 5000))
server_socket.listen(1)
print("Server listening on port 5000...")
conn, addr = server_socket.accept()
print(f"Connected by {addr}")
data = conn.recv(1024)
print(f"Encrypted data received by server is: {data.decode()}")
decrypted_text = decrypt_message(data.decode())
print(f"AFTER Decryption message is: {decrypted_text}")

conn.close()
server_socket.close()