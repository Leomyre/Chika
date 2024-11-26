import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt_message(plain_text, password):
    # Générer un sel et un IV
    salt = os.urandom(16)
    iv = os.urandom(16)

    # Clé dérivée
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Chiffrement
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding des données avant chiffrement
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    # Chiffrement des données
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

    # Retourner le message chiffré avec le sel et l'IV encodés en Base64
    return f"{base64.b64encode(salt).decode()}:{base64.b64encode(iv).decode()}:{base64.b64encode(encrypted_message).decode()}"

def decrypt_message(encrypted_text, password):
    try:
        # Séparer les composants
        salt_base64, iv_base64, encrypted_message_base64 = encrypted_text.split(":")
        salt = base64.b64decode(salt_base64)
        iv = base64.b64decode(iv_base64)
        encrypted_message = base64.b64decode(encrypted_message_base64)

        print(f"Salt: {salt} (len: {len(salt)})")
        print(f"IV: {iv} (len: {len(iv)})")
        print(f"Encrypted Message: {encrypted_message} (len: {len(encrypted_message)})")

        # Clé dérivée
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())

        # Déchiffrement
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Déchiffrement des données
        decrypted_padded_data = decryptor.update(encrypted_message) + decryptor.finalize()

        # Retrait du padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return decrypted_data.decode('utf-8')

    except Exception as e:
        print(f"Failed to decrypt: {e}")
        raise


def check_encryption_consistency(plain_text, encrypted_text, password):
    encrypted = encrypt_message(plain_text, password)
    print(f"Encrypted (for check): {encrypted}")
    
    decrypted = decrypt_message(encrypted_text, password)
    print(f"Decrypted (for check): {decrypted}")
    
    return decrypted == plain_text
