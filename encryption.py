import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 600_000
FORMAT_VERSION = 1


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password_bytes)
    del password_bytes
    return key


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key_from_password(password, salt)
    aead = ChaCha20Poly1305(key)

    with open(output_path, 'wb') as out:
        out.write(bytes([FORMAT_VERSION]))
        out.write(salt)
        out.write(nonce)

        with open(input_path, 'rb') as inp:
            plaintext = inp.read()
            ciphertext = aead.encrypt(nonce, plaintext, None)
            out.write(ciphertext)

    # try to remove sensitive material from memory
    try:
        del key, plaintext, ciphertext
    except Exception:
        pass
