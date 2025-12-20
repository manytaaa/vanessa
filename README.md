# Vanessa - File Encryption Tool

A simple command-line file encryption tool using ChaCha20-Poly1305 (AEAD) with PBKDF2 key derivation.

## What is this?

Vanessa encrypts and decrypts files using authenticated encryption:

- **ChaCha20-Poly1305 (AEAD)**: Authenticated ChaCha20 construction (256-bit key)
- **PBKDF2-HMAC-SHA256**: Password-based key derivation (600,000 iterations)
- **Random salt & nonce**: Every encryption is unique

## Requirements

- Python 3.7 or higher
- `cryptography` library

## Installation

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Encrypt a file

```bash
python vanessa.py encrypt <input_file> <output_file>
```

Example:

```bash
python vanessa.py encrypt secret.txt secret.enc
```

You'll be prompted to enter and confirm a password.

### Decrypt a file

```bash
python vanessa.py decrypt <input_file> <output_file>
```

Example:

```bash
python vanessa.py decrypt secret.enc decrypted.txt
```

You'll be prompted to enter the password.

## Testing

Quick test:

```bash
# Create test file
echo "Secret message" > test.txt

# Encrypt
python vanessa.py encrypt test.txt test.enc

# Decrypt
python vanessa.py decrypt test.enc result.txt

# Verify
type result.txt
```

## Project Structure

Short layout of the main files you will interact with:

- `vanessa.py`: CLI entrypoint — parses arguments and calls the encryption/decryption helpers
- `encryption.py`: Implements `encrypt_file()`, key derivation and crypto constants
- `decryption.py`: Implements `decrypt_file()` and handles reading the file header
- `requirements.txt`: Python dependency list (cryptography)

## Developer Notes

- `encryption.py` exposes `SALT_SIZE`, `NONCE_SIZE`, and `FORMAT_VERSION` used by the CLI.
- The CLI (`vanessa.py`) performs a quick file-format `version` check before calling `decrypt_file()`.
- If you modify constants (salt/nonce sizes or format version), update both modules and the README.

## Technical Details

### File Format

Encrypted files produced by the code have this structure:

```
[1 byte: version] [16 bytes: salt] [12 bytes: nonce] [N bytes: ciphertext+tag]
```

Notes:
- The project uses ChaCha20-Poly1305 (AEAD). The authentication tag is appended to the ciphertext (handled by the library).
- Nonce size follows the IETF ChaCha20-Poly1305 standard: 12 bytes (96 bits).

### Encryption Process

1. Generate random 16-byte salt
2. Derive a 256-bit key from the password using PBKDF2-HMAC-SHA256 (600,000 iterations)
3. Generate random 12-byte nonce
4. Encrypt with ChaCha20-Poly1305 (provides confidentiality + integrity)
5. Write: version + salt + nonce + ciphertext (which includes the authentication tag)

### Decryption Process

1. Read encrypted file header (version, salt, nonce)
2. Derive the same key from the password and salt
3. Decrypt with ChaCha20-Poly1305 (will fail if password is wrong or data tampered)

## Security Notes

**Strengths:**

- Authenticated encryption (ChaCha20-Poly1305) — tampering or wrong passwords produce a decryption error
- Password never stored
- Unique encryption each time (random salt/nonce)
- 600,000 PBKDF2 iterations slow down brute-force

**Limitations & Recommendations:**

- PBKDF2 is CPU-bound; for production consider a memory-hard KDF such as Argon2
- Consider explicit versioning and larger associated-data handling if you need metadata integrity
- Perform a security audit before using for sensitive production data

**Password tips:**

- Use strong, unique passwords
- Mix letters, numbers, and symbols
- Longer is better
- If you forget it, the file is unrecoverable

## For Production

Consider these improvements:

- **Argon2** for memory-hard key derivation
- Strong key management and secure password handling
- Formal security review / audit