from flask import Flask, render_template, request, redirect, url_for, make_response, flash
import hashlib
import os
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import base64

app = Flask(__name__)

# Metodo nuevo para leer variables de entorno
def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value

# (CWE-259 — Hardcoded Credentials) Leer el secret key de la variable de entorno definida en el archivo .env
app.secret_key = require_env("FLASK_SECRET_KEY")

# Vulnerable: Storing user data in memory
users = {
    'admin': {
        'password_hash': generate_password_hash(require_env("ADMIN_PASSWORD")), # (CWE-259 — Hardcoded Credentials) Leer de la variable de entorno
        'email': 'admin@example.com',
        'role': 'admin'
    },
    'user': {
        'password_hash': generate_password_hash(require_env("USER_PASSWORD")), # (CWE-259 — Hardcoded Credentials) Leer de la variable de entorno
        'email': 'user@example.com',
        'role': 'user'
    }
}

# Vulnerable: Storing reset tokens in memory
password_reset_tokens = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/lab')
def lab():
    return render_template('lab.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    remember_me = request.form.get('remember_me')

    # (CWE-259 — Hardcoded Credentials) Chequear contraseña con hash
    if username in users and check_password_hash(users[username]['password_hash'], password):
        response = make_response(redirect(url_for('dashboard')))
        
        # Vulnerable: Insecure session management
        session_token = base64.b64encode(f"{username}:{datetime.now()}".encode()).decode()
        
        if remember_me:
            # Vulnerable: Insecure "Remember Me" implementation
            response.set_cookie('session', session_token, max_age=30*24*60*60)
        else:
            response.set_cookie('session', session_token)
            
        return response
    
    flash('Invalid username or password')
    return redirect(url_for('lab'))

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    
    # Vulnerable: No password complexity requirements
    if username and password and email:
        if username not in users:
            users[username] = {
                'password': password,  # Vulnerable: Storing plain text passwords
                'email': email,
                'role': 'user'
            }
            flash('Registration successful')
            return redirect(url_for('lab'))
    
    flash('Registration failed')
    return redirect(url_for('lab'))

@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form.get('email')
    
    # Vulnerable: Password reset token generation
    for username, user_data in users.items():
        if user_data['email'] == email:
            # (CWE-327 — Criptografía débil (MD5)) generar token no predecible
            token = secrets.token_urlsafe(32)
            password_reset_tokens[token] = username
            
            # In a real application, this would send an email
            # Vulnerable: Token exposed in response
            flash(f'Password reset link: /reset/{token}')
            return redirect(url_for('lab'))
    
    flash('Email not found')
    return redirect(url_for('lab'))

@app.route('/reset/<token>')
def reset_form(token):
    if token in password_reset_tokens:
        return render_template('reset.html', token=token)
    return 'Invalid token'

@app.route('/dashboard')
def dashboard():
    session_token = request.cookies.get('session')
    if not session_token:
        return redirect(url_for('lab'))
    
    try:
        # Vulnerable: Insecure session validation
        username = base64.b64decode(session_token).decode().split(':')[0]
        if username in users:
            return render_template('dashboard.html', 
                                username=username, 
                                role=users[username]['role'],
                                email=users[username]['email'])
    except:
        pass
    
    return redirect(url_for('lab'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)  # Vulnerable: Debug mode enabled in production 