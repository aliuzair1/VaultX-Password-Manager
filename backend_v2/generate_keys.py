#!/usr/bin/env python3
"""
Utility script to generate secure keys for VaultX
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import secrets

def generate_master_encryption_key():
    """Generate a 256-bit AES key for master encryption"""
    key = AESGCM.generate_key(bit_length=256)
    return base64.b64encode(key).decode()

def generate_jwt_secret():
    """Generate a secure random string for JWT secret"""
    return secrets.token_urlsafe(32)

if __name__ == "__main__":
    print("VaultX Security Keys Generator")
    print("=" * 50)
    print("\nGenerated Keys (Add these to your .env file):\n")
    
    print("JWT_SECRET_KEY=" + generate_jwt_secret())
    print("MASTER_ENCRYPTION_KEY=" + generate_master_encryption_key())
    
    print("\n" + "=" * 50)
    print("⚠️  IMPORTANT: Keep these keys secret and secure!")
    print("⚠️  Never commit these keys to version control!")
