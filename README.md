# Vanessa - File Encryption Tool

A simple command-line file encryption tool using ChaCha20 cipher with PBKDF2 key derivation.

## What is this?

Vanessa encrypts and decrypts files using strong cryptography:

- **ChaCha20**: Modern stream cipher (256-bit keys)
- **PBKDF2**: Password-based key derivation (600,000 iterations)
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

## Technical Details

### File Format

Encrypted files structure:

```
[1 byte: version] [16 bytes: salt] [16 bytes: nonce] [N bytes: ciphertext]
```

### Encryption Process

1. Generate random 16-byte salt
2. Derive 256-bit key from password using PBKDF2-HMAC-SHA256 (600,000 iterations)
3. Generate random 16-byte nonce
4. Encrypt with ChaCha20
5. Write: version + salt + nonce + ciphertext

### Decryption Process

1. Read encrypted file
2. Extract salt and nonce from header
3. Derive same key from password + salt
4. Decrypt with ChaCha20

## Security Notes

**Strengths:**

- Strong 256-bit encryption
- Password never stored
- Unique encryption each time (random salt/nonce)
- 600,000 PBKDF2 iterations slow down brute-force

**Limitations:**

- No authentication (wrong password produces garbage, not an error)
- No integrity checking (can't detect tampering)
- Educational tool - not for production

**Password tips:**

- Use strong, unique passwords
- Mix letters, numbers, and symbols
- Longer is better
- If you forget it, the file is unrecoverable

## For Production

Consider these improvements:

- **ChaCha20-Poly1305** for authenticated encryption (AEAD)
- **Argon2** for memory-hard key derivation
- Proper key management
- Security audit

