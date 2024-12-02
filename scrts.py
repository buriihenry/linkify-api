import secrets

# Generate a random secret key to use as the encryption key for JWT_SECRET_KEY
secret_key = secrets.token_urlsafe(32)  # 32 bytes long
print(secret_key)
