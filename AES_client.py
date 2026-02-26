# -*- coding: utf-8 -*-
"""
Created on Wed Feb 25 23:34:31 2026

@author: sidra
"""

import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

KEY = b'12345678901234567890123456789012'    # 32 bytes for AES
IV = b'1234567890123456'                     # 16 bytes IV

def encrypt_message(msg):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded_msg = pad(msg.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded_msg)
    return base64.b64encode(encrypted).decode('utf-8')

# Create TCP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 5000))
message = input("Enter Message:")
encrypted_msg = encrypt_message(message)
print(f"Encrypted Message sent by client: {encrypted_msg}")
client_socket.sendall(encrypted_msg.encode())
client_socket.close()