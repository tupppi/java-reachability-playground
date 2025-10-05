#!/usr/bin/env python3
"""
SUPER VULNERABLE Flask Web Application for DAST Testing
Contains multiple obvious security vulnerabilities that OWASP ZAP will definitely find.
"""

from flask import Flask, request, render_template_string, redirect, url_for, session, make_response
import os
import subprocess
import pickle
import base64
import sqlite3
from urllib.parse import unquote

app = Flask(__name__)
app.secret_key = '123456'  # Vulnerability 1: Extremely weak secret key

# SECRETS FOR TESTING SECRETS SCANNING - DO NOT COMMIT TO PRODUCTION!
API_KEY = "sk-TEST_TOKEN_NOT_REAL_1234567890abcdef"
DATABASE_PASSWORD = "super_secret_db_password_123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
GITHUB_TOKEN = "ghp-TEST_TOKEN_NOT_REAL_1234567890abcdef"

# Create a simple database for SQL injection testing
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    cursor.execute('INSERT OR IGNORE INTO users (username, password) VALUES ("admin", "admin123")')
    cursor.execute('INSERT OR IGNORE INTO users (username, password) VALUES ("user", "password")')
    conn.commit()
    conn.close()

# Vulnerability 1: SQL Injection (High Risk)
@app.route('/login')
def login():
    username = request.args.get('user', '')
    password = request.args.get('pass', '')
    
    # EXTREMELY vulnerable SQL query - no sanitization
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return f"<h1>Login Successful!</h1><p>Welcome {username}</p><p>Query executed: {query}</p>"
        else:
            return f"<h1>Login Failed</h1><p>Invalid credentials</p><p>Query executed: {query}</p>"
    except Exception as e:
        return f"<h1>Database Error</h1><p>Error: {str(e)}</p><p>Query: {query}</p>"

# Vulnerability 2: Command Injection (High Risk)
@app.route('/exec')
def exec_cmd():
    cmd = request.args.get('cmd', '')
    # EXTREMELY dangerous - direct command execution
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        return f"<h1>Command Executed</h1><pre>Command: {cmd}\nOutput:\n{result}</pre>"
    except Exception as e:
        return f"<h1>Command Error</h1><p>Error: {str(e)}</p><p>Command: {cmd}</p>"

# Vulnerability 3: XSS - Reflected (High Risk)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # NO sanitization - direct output
    return f"""
    <h1>Search Results</h1>
    <p>You searched for: {query}</p>
    <p>Results for "{query}" not found.</p>
    """

# Vulnerability 4: XSS - Stored (High Risk)
@app.route('/guestbook', methods=['GET', 'POST'])
def guestbook():
    if request.method == 'POST':
        name = request.form.get('name', '')
        message = request.form.get('message', '')
        # Store without sanitization
        with open('guestbook.txt', 'a') as f:
            f.write(f"<div><strong>{name}:</strong> {message}</div>\n")
    
    # Read and display without sanitization
    try:
        with open('guestbook.txt', 'r') as f:
            entries = f.read()
    except:
        entries = "No entries yet."
    
    return f"""
    <h1>Guestbook</h1>
    <form method="POST">
        <input type="text" name="name" placeholder="Your name" required><br><br>
        <textarea name="message" placeholder="Your message" required></textarea><br><br>
        <input type="submit" value="Post Message">
    </form>
    <hr>
    <h2>Messages:</h2>
    <div>{entries}</div>
    """

# Vulnerability 5: Information Disclosure (Medium Risk)
@app.route('/config')
def config():
    # Expose ALL environment variables and system info
    return f"""
    <h1>System Configuration</h1>
    <h2>Environment Variables:</h2>
    <pre>{dict(os.environ)}</pre>
    <h2>System Information:</h2>
    <pre>Current Directory: {os.getcwd()}
Python Path: {os.sys.path}
Process ID: {os.getpid()}</pre>
    """

# Vulnerability 6: Path Traversal (High Risk)
@app.route('/read')
def read_file():
    filename = request.args.get('file', 'index.txt')
    # NO path validation
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"<h1>File Contents</h1><p>Reading: {filename}</p><pre>{content}</pre>"
    except Exception as e:
        return f"<h1>Error</h1><p>Could not read {filename}: {str(e)}</p>"

# Vulnerability 7: Weak Authentication (Medium Risk)
@app.route('/admin')
def admin():
    # Simple password check - easily bypassed
    if request.args.get('password') == 'admin':
        return """
        <h1>Admin Panel</h1>
        <p>Welcome Administrator!</p>
        <p>Database: admin/admin123</p>
        <p>Secret API Key: sk-1234567890abcdef</p>
        <p><a href="/config">System Config</a></p>
        <p><a href="/exec?cmd=whoami">Run Command</a></p>
        """
    return """
    <h1>Admin Login</h1>
    <p>Password: admin</p>
    <a href="/admin?password=admin">Login as Admin</a>
    """

# Vulnerability 8: CSRF (Cross-Site Request Forgery) - Medium Risk
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if request.method == 'POST':
        amount = request.form.get('amount', '')
        to = request.form.get('to', '')
        # NO CSRF protection
        return f"<h1>Transfer Complete</h1><p>Transferred ${amount} to {to}</p>"
    
    return """
    <h1>Money Transfer</h1>
    <form method="POST">
        <input type="text" name="to" placeholder="Recipient" required><br>
        <input type="text" name="amount" placeholder="Amount" required><br>
        <input type="submit" value="Transfer">
    </form>
    """

# Vulnerability 9: Insecure Direct Object Reference
@app.route('/user/<user_id>')
def user_profile(user_id):
    # NO authorization check
    return f"""
    <h1>User Profile</h1>
    <p>User ID: {user_id}</p>
    <p>Email: user{user_id}@example.com</p>
    <p>Balance: $10000</p>
    <p>SSN: 123-45-6789</p>
    """

# Vulnerability 10: Directory Listing
@app.route('/files')
def list_files():
    # Expose directory contents
    files = os.listdir('.')
    file_list = '<br>'.join([f'<a href="/read?file={f}">{f}</a>' for f in files])
    return f"<h1>Files in Directory</h1><p>{file_list}</p>"

# Home page with links to ALL vulnerable endpoints
@app.route('/')
def index():
    return """
    <h1>🚨 SUPER VULNERABLE Web Application 🚨</h1>
    <p><strong>EXTREMELY VULNERABLE - For DAST Testing Only!</strong></p>
    
    <h2>🔴 High Risk Vulnerabilities:</h2>
    <ul>
        <li><a href="/login?user=admin&pass=admin">SQL Injection</a> - Try: <code>/login?user=admin' OR '1'='1'--&pass=anything</code></li>
        <li><a href="/exec?cmd=whoami">Command Injection</a> - Try: <code>/exec?cmd=ls -la</code></li>
        <li><a href="/search?q=test">Reflected XSS</a> - Try: <code>/search?q=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
        <li><a href="/read?file=index.txt">Path Traversal</a> - Try: <code>/read?file=../../../etc/passwd</code></li>
    </ul>
    
    <h2>🟡 Medium Risk Vulnerabilities:</h2>
    <ul>
        <li><a href="/guestbook">Stored XSS</a> - Post: <code>&lt;script&gt;alert('Stored XSS')&lt;/script&gt;</code></li>
        <li><a href="/config">Information Disclosure</a></li>
        <li><a href="/admin">Weak Authentication</a></li>
        <li><a href="/transfer">CSRF</a></li>
    </ul>
    
    <h2>🔵 Other Vulnerabilities:</h2>
    <ul>
        <li><a href="/user/1">Insecure Direct Object Reference</a></li>
        <li><a href="/files">Directory Listing</a></li>
    </ul>
    
    <h2>🎯 ZAP Testing Tips:</h2>
    <p>This app is designed to trigger OWASP ZAP alerts. Try the links above!</p>
    """

if __name__ == '__main__':
    # Create a simple test file for path traversal testing
    with open('index.txt', 'w') as f:
        f.write('This is a test file for path traversal vulnerability testing.')
    
    print("🚨 Starting Vulnerable Flask Application...")
    print("⚠️  WARNING: This application contains intentional security vulnerabilities!")
    print("🎯 Designed for DAST testing with OWASP ZAP")
    print("🌐 Application will be available at: http://localhost:8080")
    
    app.run(host='0.0.0.0', port=8080, debug=True)  # Debug=True is also a vulnerability
