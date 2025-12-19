import os
import sys
import argparse
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 


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
    print(f"[*] Encrypting: {input_path}")

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    print(f"[+] Generated salt & nonce")

    key = derive_key_from_password(password, salt)
    aead = ChaCha20Poly1305(key)

    print(f"[+] Derived key using PBKDF2")
    
    with open(output_path, 'wb') as out:
        out.write(bytes([FORMAT_VERSION]))
        out.write(salt)
        out.write(nonce)

        with open(input_path, 'rb') as inp:
            plaintext = inp.read()
            ciphertext = aead.encrypt(nonce, plaintext, None)
            out.write(ciphertext)

    print(f"[✓] Encryption successful ({os.path.getsize(output_path)} bytes)")
    del key, plaintext, ciphertext


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    print(f"[*] Decrypting: {input_path}")

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    with open(input_path, 'rb') as f:
        version = f.read(1)[0]
        if version != FORMAT_VERSION:
            raise ValueError("Unsupported format version")

        salt = f.read(SALT_SIZE)
        nonce = f.read(NONCE_SIZE)
        ciphertext = f.read()

    key = derive_key_from_password(password, salt)
    aead = ChaCha20Poly1305(key)

    print(f"[+] Derived key using PBKDF2")

    try:
        plaintext = aead.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed (wrong password or tampered data)")

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    print(f"[✓] Decryption successful ({len(plaintext)} bytes)")
    del key, plaintext, ciphertext


def main():
    parser = argparse.ArgumentParser(
        prog='vanessa',
        description='Vanessa - File Encryption Tool (ChaCha20 + PBKDF2)',
        epilog='Example: python vanessa.py encrypt secret.txt secret.enc'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
 
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('input_file', help='File to encrypt')
    encrypt_parser.add_argument('output_file', help='Output file')

    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('input_file', help='File to decrypt')
    decrypt_parser.add_argument('output_file', help='Output file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    print("=" * 60)
    print("  VANESSA - File Encryption Tool")
    print("=" * 60)
    print()
    
    try:
        password = getpass.getpass("Enter password: ")
        
        if not password:
            print("[!] Error: Password cannot be empty")
            sys.exit(1)
        
        if args.command == 'encrypt':
            password_confirm = getpass.getpass("Confirm password: ")
            if password != password_confirm:
                print("[!] Error: Passwords do not match")
                sys.exit(1)
            del password_confirm
        
        print()
        
        if args.command == 'encrypt':
            encrypt_file(args.input_file, args.output_file, password)
        elif args.command == 'decrypt':
            decrypt_file(args.input_file, args.output_file, password)
        
        del password
        
    except FileNotFoundError as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
    except PermissionError as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n[!] Cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
    
    print()
    print("=" * 60)


if __name__ == '__main__':
    main()
