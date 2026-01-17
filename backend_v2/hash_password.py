#!/usr/bin/env python3
"""
Utility script to generate bcrypt password hashes for VaultX users
"""
import bcrypt
import sys

def hash_password(password):
    """Generate bcrypt hash for a password"""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        password = sys.argv[1]
    else:
        password = input("Enter password to hash: ")
    
    hashed = hash_password(password)
    print(f"\nPassword: {password}")
    print(f"Bcrypt Hash: {hashed}")
    print("\nUse this hash in your database INSERT statement.")
