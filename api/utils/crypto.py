from cryptography.fernet import Fernet
import os

# الأفضل تتحط في .env
SECRET_KEY = os.getenv("FILE_ENCRYPTION_KEY")

fernet = Fernet(SECRET_KEY)


def encrypt_file(data: bytes):
    return fernet.encrypt(data)


def decrypt_file(data: bytes):
    return fernet.decrypt(data)

import hashlib

def generate_hash(data: bytes):
    return hashlib.sha256(data).hexdigest()