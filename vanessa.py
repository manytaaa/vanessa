import os
import sys
import argparse
import getpass

from encryption import SALT_SIZE, NONCE_SIZE, FORMAT_VERSION
from encryption import encrypt_file
from decryption import decrypt_file


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
            print(f"[*] Encrypting: {args.input_file}")
            encrypt_file(args.input_file, args.output_file, password)
            print(f"[✓] Encryption successful ({os.path.getsize(args.output_file)} bytes)")
        elif args.command == 'decrypt':
            print(f"[*] Decrypting: {args.input_file}")
            with open(args.input_file, 'rb') as f:
                version = f.read(1)[0]
                if version != FORMAT_VERSION:
                    raise ValueError("Unsupported format version")
            decrypt_file(args.input_file, args.output_file, password)
            print(f"[✓] Decryption successful ({os.path.getsize(args.output_file)} bytes)")
        
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
