import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from encryption import derive_key_from_password


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    with open(input_path, 'rb') as f:
        version = f.read(1)[0]
        salt = f.read(16)
        nonce = f.read(12)
        ciphertext = f.read()

    key = derive_key_from_password(password, salt)
    aead = ChaCha20Poly1305(key)

    try:
        plaintext = aead.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed (wrong password or tampered data)")

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    try:
        del key, plaintext, ciphertext
    except Exception:
        pass
