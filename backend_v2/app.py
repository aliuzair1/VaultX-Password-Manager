import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()

app = Flask(__name__)
CORS(app, origins=["*"], supports_credentials=True)

# Configuration
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
app.config['DATABASE_URL'] = os.getenv('DATABASE_URL')

# Database connection
def get_db_connection():
    conn = psycopg.connect(app.config['DATABASE_URL'], row_factory=dict_row)
    return conn

# Encryption utilities
class EncryptionManager:
    def __init__(self):
        self.master_key = os.getenv('MASTER_ENCRYPTION_KEY')
        if not self.master_key:
            raise ValueError("MASTER_ENCRYPTION_KEY not set")
        self.master_key = base64.b64decode(self.master_key)
    
    def generate_user_key(self):
        """Generate a unique encryption key for each user"""
        return AESGCM.generate_key(bit_length=256)
    
    def encrypt_data(self, data, key):
        """Encrypt data using AES-256-GCM"""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
        # Return nonce + ciphertext as base64
        return base64.b64encode(nonce + ciphertext).decode()
    
    def decrypt_data(self, encrypted_data, key):
        """Decrypt data using AES-256-GCM"""
        try:
            data = base64.b64decode(encrypted_data)
            nonce = data[:12]
            ciphertext = data[12:]
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
        except Exception as e:
            raise ValueError("Decryption failed")

encryption_manager = EncryptionManager()

# JWT Token utilities
def generate_token(user_id, username):
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = {
                'user_id': data['user_id'],
                'username': data['username']
            }
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def get_user_key(conn, user_id):
    """Get or create encryption key for user"""
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute('SELECT id, key_data FROM encryption_keys WHERE user_id = %s', (user_id,))
    key_record = cur.fetchone()
    
    if not key_record:
        # Generate new key for user
        user_key = encryption_manager.generate_user_key()
        user_key_encrypted = encryption_manager.encrypt_data(
            base64.b64encode(user_key).decode(),
            encryption_manager.master_key
        )
        cur.execute(
            'INSERT INTO encryption_keys (user_id, key_data) VALUES (%s, %s) RETURNING id',
            (user_id, user_key_encrypted)
        )
        key_id = cur.fetchone()['id']
        conn.commit()
    else:
        key_id = key_record['id']
        # Decrypt user key
        user_key_b64 = encryption_manager.decrypt_data(key_record['key_data'], encryption_manager.master_key)
        user_key = base64.b64decode(user_key_b64)
    
    cur.close()
    return key_id, user_key

def normalize_url(url):
    """Normalize URL to domain"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain.lower()
    except:
        return url.lower()

# Routes
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor(row_factory=dict_row)
        
        cur.execute('SELECT id, username, password_hash FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Verify password
        if not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Generate token
        token = generate_token(user['id'], user['username'])
        
        return jsonify({
            'token': token,
            'username': user['username']
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/auth/verify', methods=['GET'])
@token_required
def verify_token(current_user):
    return jsonify({'valid': True, 'username': current_user['username']}), 200

@app.route('/api/credentials/save', methods=['POST'])
@token_required
def save_credential(current_user):
    """Save credential from extension or manual add"""
    print("=" * 50)
    print("SAVE CREDENTIAL STARTED")
    print("=" * 50)
    
    data = request.get_json()
    
    website_url = data.get('website_url', '').strip()
    website_name = data.get('website_name', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    print(f"Website URL: {website_url}")
    print(f"Website Name: {website_name}")
    print(f"Username: {username}")
    print(f"Password length: {len(password)}")
    
    if not website_url or not username or not password:
        print("ERROR: Missing required fields")
        return jsonify({'error': 'Website URL, username and password required'}), 400
    
    try:
        print("Step 1: Connecting to database...")
        conn = get_db_connection()
        print("Step 1: SUCCESS")
        
        # Check if site is excluded
        print("Step 2: Checking excluded sites...")
        cur = conn.cursor(row_factory=dict_row)
        domain = normalize_url(website_url)
        
        try:
            cur.execute(
                'SELECT id FROM excluded_sites WHERE user_id = %s AND domain = %s',
                (current_user['user_id'], domain)
            )
            if cur.fetchone():
                cur.close()
                conn.close()
                print("ERROR: Site is excluded")
                return jsonify({'error': 'This site is in your excluded list'}), 403
        except Exception as e:
            print(f"Excluded sites check failed (table might not exist): {e}")
            # Continue anyway - excluded_sites is optional
        
        print("Step 2: SUCCESS")
        
        # Get or create encryption key
        print("Step 3: Getting encryption key...")
        try:
            key_id, user_key = get_user_key(conn, current_user['user_id'])
            print(f"Step 3: SUCCESS - Key ID: {key_id}")
        except Exception as e:
            print(f"Step 3: FAILED - {str(e)}")
            print("Attempting to create new key...")
            
            # Create encryption key for user
            user_key = encryption_manager.generate_user_key()
            user_key_encrypted = encryption_manager.encrypt_data(
                base64.b64encode(user_key).decode(),
                encryption_manager.master_key
            )
            
            cur = conn.cursor(row_factory=dict_row)
            cur.execute(
                'INSERT INTO encryption_keys (user_id, key_data) VALUES (%s, %s) RETURNING id',
                (current_user['user_id'], user_key_encrypted)
            )
            key_result = cur.fetchone()
            key_id = key_result['id']
            conn.commit()
            print(f"Step 3: Created new key - Key ID: {key_id}")
        
        # Check if credential already exists for this site
        print("Step 4: Checking for existing credential...")
        cur = conn.cursor(row_factory=dict_row)
        cur.execute(
            '''SELECT id FROM credentials 
               WHERE user_id = %s AND website_url = %s AND username = %s''',
            (current_user['user_id'], website_url, username)
        )
        existing = cur.fetchone()
        print(f"Step 4: Existing credential: {existing is not None}")
        
        # Encrypt password
        print("Step 5: Encrypting password...")
        encrypted_password = encryption_manager.encrypt_data(password, user_key)
        print("Step 5: SUCCESS")
        
        if existing:
            # Update existing credential
            print("Step 6: Updating existing credential...")
            cur.execute(
                '''UPDATE credentials 
                   SET encrypted_password = %s, website_name = %s, updated_at = CURRENT_TIMESTAMP
                   WHERE id = %s
                   RETURNING id''',
                (encrypted_password, website_name or domain, existing['id'])
            )
            cred_id = cur.fetchone()['id']
            message = 'Credential updated successfully'
            print("Step 6: SUCCESS - Updated")
        else:
            # Insert new credential
            print("Step 6: Inserting new credential...")
            cur.execute(
                '''INSERT INTO credentials 
                   (user_id, website_url, website_name, username, encrypted_password, encryption_key_id)
                   VALUES (%s, %s, %s, %s, %s, %s)
                   RETURNING id''',
                (current_user['user_id'], website_url, website_name or domain, 
                 username, encrypted_password, key_id)
            )
            cred_id = cur.fetchone()['id']
            message = 'Credential saved successfully'
            print("Step 6: SUCCESS - Inserted")
        
        conn.commit()
        cur.close()
        conn.close()
        
        print("=" * 50)
        print("SAVE CREDENTIAL SUCCESSFUL")
        print("=" * 50)
        
        return jsonify({
            'success': True,
            'message': message,
            'credential_id': cred_id
        }), 200
        
    except Exception as e:
        print("=" * 50)
        print("FATAL ERROR IN SAVE")
        print("=" * 50)
        print(f"Error: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        print(traceback.format_exc())
        print("=" * 50)
        return jsonify({'error': 'Failed to save credential'}), 500

@app.route('/api/credentials/list', methods=['GET'])
@token_required
def list_credentials(current_user):
    try:
        conn = get_db_connection()
        cur = conn.cursor(row_factory=dict_row)
        
        # Try to get all credentials, handling missing columns gracefully
        try:
            cur.execute(
                '''SELECT id, website_url, website_name, username, created_at, updated_at
                   FROM credentials WHERE user_id = %s 
                   ORDER BY updated_at DESC NULLS LAST''',
                (current_user['user_id'],)
            )
        except Exception as e:
            # If query fails (missing columns), try simpler query
            print(f"First query failed: {e}")
            cur.execute(
                '''SELECT id, username, created_at
                   FROM credentials WHERE user_id = %s 
                   ORDER BY created_at DESC''',
                (current_user['user_id'],)
            )
        
        credentials = cur.fetchall()
        
        cur.close()
        conn.close()
        
        # Build response with safe defaults for missing fields
        result = []
        for cred in credentials:
            result.append({
                'id': cred.get('id'),
                'websiteUrl': cred.get('website_url', 'Not specified'),
                'websiteName': cred.get('website_name', cred.get('username', 'Unknown')),
                'username': cred.get('username', 'Unknown'),
                'createdAt': cred.get('created_at').isoformat() if cred.get('created_at') else None,
                'updatedAt': cred.get('updated_at').isoformat() if cred.get('updated_at') else None
            })
        
        return jsonify({'credentials': result}), 200
        
    except Exception as e:
        print(f"Error in list_credentials: {str(e)}")
        import traceback
        print(traceback.format_exc())
        # Return empty list instead of error
        return jsonify({'credentials': []}), 200

@app.route('/api/credentials/decrypt/<int:cred_id>', methods=['GET'])
@token_required
def decrypt_credential(current_user, cred_id):
    print("=" * 50)
    print(f"DECRYPT CREDENTIAL ID: {cred_id}")
    print("=" * 50)
    
    try:
        print("Step 1: Connecting to database...")
        conn = get_db_connection()
        cur = conn.cursor(row_factory=dict_row)
        print("Step 1: SUCCESS")
        
        # Fetch credential with encryption key
        print("Step 2: Fetching credential...")
        try:
            # Try with all fields first
            cur.execute(
                '''SELECT c.id, c.website_url, c.website_name, c.username, 
                          c.encrypted_password, ek.key_data
                   FROM credentials c
                   JOIN encryption_keys ek ON c.encryption_key_id = ek.id
                   WHERE c.id = %s AND c.user_id = %s''',
                (cred_id, current_user['user_id'])
            )
        except Exception as e:
            print(f"Full query failed: {e}")
            # Try simpler query without website fields
            cur.execute(
                '''SELECT c.id, c.username, c.encrypted_password, ek.key_data
                   FROM credentials c
                   JOIN encryption_keys ek ON c.encryption_key_id = ek.id
                   WHERE c.id = %s AND c.user_id = %s''',
                (cred_id, current_user['user_id'])
            )
        
        credential = cur.fetchone()
        print(f"Step 2: Credential found: {credential is not None}")
        
        cur.close()
        conn.close()
        
        if not credential:
            print("ERROR: Credential not found")
            return jsonify({'error': 'Credential not found'}), 404
        
        print("Step 3: Decrypting user key...")
        # Decrypt user key
        user_key_b64 = encryption_manager.decrypt_data(credential['key_data'], encryption_manager.master_key)
        user_key = base64.b64decode(user_key_b64)
        print("Step 3: SUCCESS")
        
        print("Step 4: Decrypting password...")
        # Decrypt password
        decrypted_password = encryption_manager.decrypt_data(credential['encrypted_password'], user_key)
        print("Step 4: SUCCESS")
        
        print("=" * 50)
        print("DECRYPT SUCCESSFUL")
        print("=" * 50)
        
        return jsonify({
            'id': credential.get('id'),
            'websiteUrl': credential.get('website_url', 'Not specified'),
            'websiteName': credential.get('website_name', credential.get('username', 'Unknown')),
            'username': credential.get('username', 'Unknown'),
            'password': decrypted_password
        }), 200
        
    except Exception as e:
        print("=" * 50)
        print("FATAL ERROR IN DECRYPT")
        print("=" * 50)
        print(f"Error: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        print(traceback.format_exc())
        print("=" * 50)
        return jsonify({'error': 'Failed to decrypt credential'}), 500
        
@app.route('/api/credentials/for-site', methods=['POST'])
@token_required
def get_credentials_for_site(current_user):
    """Get credentials for a specific website (for auto-fill)"""
    data = request.get_json()
    website_url = data.get('website_url', '').strip()
    
    if not website_url:
        return jsonify({'error': 'Website URL required'}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Normalize URL to match stored credentials
        domain = normalize_url(website_url)
        
        # Find credentials for this domain
        cur.execute(
            '''SELECT c.id, c.website_url, c.website_name, c.username, 
                      c.encrypted_password, ek.key_data
               FROM credentials c
               JOIN encryption_keys ek ON c.encryption_key_id = ek.id
               WHERE c.user_id = %s AND (
                   c.website_url LIKE %s OR 
                   c.website_url LIKE %s
               )
               ORDER BY c.updated_at DESC''',
            (current_user['user_id'], f'%{domain}%', f'%{website_url}%')
        )
        credentials = cur.fetchall()
        
        cur.close()
        conn.close()
        
        if not credentials:
            return jsonify({'credentials': []}), 200
        
        # Decrypt passwords
        result = []
        for cred in credentials:
            user_key_b64 = encryption_manager.decrypt_data(cred['key_data'], encryption_manager.master_key)
            user_key = base64.b64decode(user_key_b64)
            decrypted_password = encryption_manager.decrypt_data(cred['encrypted_password'], user_key)
            
            result.append({
                'id': cred['id'],
                'websiteUrl': cred['website_url'],
                'websiteName': cred['website_name'],
                'username': cred['username'],
                'password': decrypted_password
            })
        
        return jsonify({'credentials': result}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch credentials'}), 500

@app.route('/api/credentials/delete/<int:cred_id>', methods=['DELETE'])
@token_required
def delete_credential(current_user, cred_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute(
            'DELETE FROM credentials WHERE id = %s AND user_id = %s RETURNING id',
            (cred_id, current_user['user_id'])
        )
        deleted = cur.fetchone()
        
        conn.commit()
        cur.close()
        conn.close()
        
        if not deleted:
            return jsonify({'error': 'Credential not found'}), 404
        
        return jsonify({'success': True, 'message': 'Credential deleted'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to delete credential'}), 500

@app.route('/api/excluded-sites/add', methods=['POST'])
@token_required
def add_excluded_site(current_user):
    data = request.get_json()
    website_url = data.get('website_url', '').strip()
    
    if not website_url:
        return jsonify({'error': 'Website URL required'}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        domain = normalize_url(website_url)
        
        # Check if already excluded
        cur.execute(
            'SELECT id FROM excluded_sites WHERE user_id = %s AND domain = %s',
            (current_user['user_id'], domain)
        )
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({'message': 'Site already excluded'}), 200
        
        # Add to excluded list
        cur.execute(
            'INSERT INTO excluded_sites (user_id, domain) VALUES (%s, %s)',
            (current_user['user_id'], domain)
        )
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Site added to excluded list'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to exclude site'}), 500

@app.route('/api/excluded-sites/list', methods=['GET'])
@token_required
def list_excluded_sites(current_user):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute(
            'SELECT id, domain, created_at FROM excluded_sites WHERE user_id = %s ORDER BY domain',
            (current_user['user_id'],)
        )
        sites = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return jsonify({
            'excludedSites': [
                {
                    'id': site['id'],
                    'domain': site['domain'],
                    'createdAt': site['created_at'].isoformat() if site['created_at'] else None
                }
                for site in sites
            ]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch excluded sites'}), 500

@app.route('/api/excluded-sites/remove/<int:site_id>', methods=['DELETE'])
@token_required
def remove_excluded_site(current_user, site_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute(
            'DELETE FROM excluded_sites WHERE id = %s AND user_id = %s RETURNING id',
            (site_id, current_user['user_id'])
        )
        deleted = cur.fetchone()
        
        conn.commit()
        cur.close()
        conn.close()
        
        if not deleted:
            return jsonify({'error': 'Site not found'}), 404
        
        return jsonify({'success': True, 'message': 'Site removed from excluded list'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to remove site'}), 500

@app.route('/api/excluded-sites/check', methods=['POST'])
@token_required
def check_excluded_site(current_user):
    """Check if a site is excluded"""
    data = request.get_json()
    website_url = data.get('website_url', '').strip()
    
    if not website_url:
        return jsonify({'error': 'Website URL required'}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        domain = normalize_url(website_url)
        cur.execute(
            'SELECT id FROM excluded_sites WHERE user_id = %s AND domain = %s',
            (current_user['user_id'], domain)
        )
        excluded = cur.fetchone()
        
        cur.close()
        conn.close()
        
        return jsonify({'excluded': excluded is not None}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to check exclusion'}), 500

@app.route('/api/password/generate', methods=['GET'])
@token_required
def generate_password(current_user):
    import secrets
    import string
    
    length = 16
    charset = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Ensure at least one character from each category
    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
    ]
    
    # Fill the rest randomly
    password += [secrets.choice(charset) for _ in range(length - 4)]
    
    # Shuffle
    secrets.SystemRandom().shuffle(password)
    
    return jsonify({'password': ''.join(password)}), 200

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
