# Secure Auth RS

Rust Axum web application implementing three-phase authentication with HTTPS/TLS security.

## HTTPS/TLS Setup

### Quick Start

1. **Generate TLS certificates** (first time only):
```bash
./generate_certs.sh
```

2. **Copy environment template**:
```bash
cp .env.example .env
```

3. **Update .env with generated values**:
The certificate generation script will output the values to add to your `.env` file.

4. **Run the server**:
```bash
cargo run
```

The server will start on `https://127.0.0.1:3443`

### Security Features

✅ **Password-protected TLS configuration** - Application-level password validation  
✅ **Certificate validation on startup** - Server refuses to start with invalid certificates  
✅ **File permission enforcement** - Private keys protected with 600 permissions  
✅ **Constant-time password comparison** - Prevents timing attacks  
✅ **Secure memory handling** - Passwords zeroized after use  
✅ **Comprehensive logging** - Security events logged without exposing secrets  

### Security Validations

The server **will not start** if:
- Certificate file is missing, invalid, or tampered with
- Private key file is missing, invalid, or tampered with  
- TLS password is incorrect or missing
- Certificate is expired
- Private key doesn't match certificate

### Testing Security

Run the comprehensive security test suite:
```bash
./test_tls_security.sh
```

Tests include:
- Valid certificate acceptance
- Invalid certificate rejection
- Missing file detection
- Incorrect password rejection
- HTTPS connectivity verification
- Certificate validity checks

### File Permissions

After running `generate_certs.sh`:
```
certs/               (drwx------)  700 - Directory access restricted to owner
certs/cert.pem       (-rw-r--r--)  644 - Public certificate
certs/key.pem        (-rw-------)  600 - Private key (owner read/write only)
certs/.key_password  (-rw-------)  600 - Password file (owner read/write only)
```

### Environment Variables

Required TLS variables in `.env`:
```env
TLS_CERT_PATH=certs/cert.pem
TLS_KEY_PATH=certs/key.pem
TLS_KEY_PASSWORD=<generated-password>
HTTPS_PORT=3443
BIND_ADDRESS=127.0.0.1
```

### Certificate Rotation

To generate new certificates:
```bash
rm -rf certs/
./generate_certs.sh
# Update .env with new TLS_KEY_PASSWORD
```

---

## USEFUL COMMANDS

### Database
```bash
sqlx migrate add -r <description>
sqlx migrate run
```

### Admin
```bash
sqlite3 auth.db "SELECT account_id, is_admin, assigned_at FROM account_roles WHERE account_id = 'EWCs3zDkrg8aTYz1';"

sqlite3 auth.db "INSERT INTO account_roles (account_id, is_admin) VALUES ('HLISi0UKcrd0sfbN', 1) ON CONFLICT(account_id) DO UPDATE SET is_admin = 1;"
```

sqlx migrate run --source migrations/auth --database-url sqlite:auth.db
   sqlx migrate run --source migrations/files --database-url sqlite:files.db
sqlx prepare --database-url sqlite:auth.db
