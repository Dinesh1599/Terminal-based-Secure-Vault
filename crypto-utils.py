from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Key Derivation

def key_derive(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


#Encryption
def encrypt_data(key: bytes, plaintext: str):
    iv = os.urandom(16)
    ciphper = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = ciphper.encryptor()
    ciphpertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64decode(iv + ciphpertext).decode()

#Decrypt
def decrypt_data(key: bytes, ciphertext: str):
    data = base64.b64decode(ciphertext.encode())
    iv = data[:16]
    cText = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(cText) + decryptor.finalize()
    return plaintext.decode()

def main():
    data = b"Secret Text"
    key = os.urandom(32)  # AES-256 requires a 32-byte key
    encrypted_data = encrypt_data(key, data)
    print(f"Encrypted Data: {encrypted_data}")

if __name__ == "__main__":
    main()
