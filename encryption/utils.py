import os
import base64
from datetime import datetime
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def generate_aes_key():
    aes_secret_key = os.urandom(32)  # 256-bit key
    return base64.b64encode(aes_secret_key).decode('utf-8'), aes_secret_key


def get_timestamp_and_ivector():
    timestamp = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
    ivector = timestamp[:16].encode('utf-8')
    return timestamp, ivector


def encrypt_payload(payload, key, iv):
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(payload.encode('utf-8')) + encryptor.finalize()
    return base64.b64encode(encryptor.tag + ciphertext).decode('utf-8')


def encrypt_aes_key(aes_secret_key, public_key_path):
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

    encrypted_aes_secret_key = public_key.encrypt(
        aes_secret_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_aes_secret_key).decode('utf-8')


def decrypt_aes_key(encrypted_aes_key_b64, private_key_path):
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    decrypted_aes_secret_key = private_key.decrypt(
        base64.b64decode(encrypted_aes_key_b64),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_aes_secret_key


def decrypt_payload(encrypted_payload, key, iv):
    encrypted_data = base64.b64decode(encrypted_payload)
    tag = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    decrypted_payload = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_payload.decode('utf-8')
