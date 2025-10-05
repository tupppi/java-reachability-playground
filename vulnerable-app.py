#!/usr/bin/env python3
"""
Intentionally Vulnerable Flask Web Application for DAST Testing
Contains multiple security vulnerabilities for educational purposes.
"""

from flask import Flask, request, render_template_string, redirect, url_for, session
import os
import subprocess
import pickle
import base64

app = Flask(__name__)
app.secret_key = 'insecure-secret-key'  # Vulnerability 1: Weak secret key

# Vulnerability 2: SQL Injection vulnerable endpoint
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Intentionally vulnerable SQL query
    sql_query = f"SELECT * FROM users WHERE name = '{query}'"
    return f"<h1>Search Results</h1><p>Executing: {sql_query}</p>"

# Vulnerability 3: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    # Intentionally vulnerable command execution
    result = os.system(f"ping -c 1 {host}")
    return f"<h1>Ping Results</h1><p>Pinged {host} with result: {result}</p>"

# Vulnerability 4: XSS (Cross-Site Scripting)
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'POST':
        comment_text = request.form.get('comment', '')
        # Intentionally vulnerable - no input sanitization
        return f"""
        <h1>Comment Posted</h1>
        <p>Your comment: {comment_text}</p>
        <a href="/comment">Post another comment</a>
        """
    return """
    <h1>Post a Comment</h1>
    <form method="POST">
        <textarea name="comment" placeholder="Enter your comment..."></textarea><br>
        <input type="submit" value="Post Comment">
    </form>
    """

# Vulnerability 5: Unsafe Deserialization
@app.route('/data')
def data():
    data_param = request.args.get('data', '')
    try:
        # Intentionally vulnerable deserialization
        decoded_data = base64.b64decode(data_param.encode()).decode()
        obj = pickle.loads(decoded_data.encode())
        return f"<h1>Data Processed</h1><p>Object: {obj}</p>"
    except Exception as e:
        return f"<h1>Error</h1><p>Failed to process data: {str(e)}</p>"

# Vulnerability 6: Information Disclosure
@app.route('/debug')
def debug():
    # Intentionally exposes sensitive information
    return f"""
    <h1>Debug Information</h1>
    <p>Environment Variables:</p>
    <pre>{dict(os.environ)}</pre>
    <p>Current Working Directory: {os.getcwd()}</p>
    <p>Python Path: {os.sys.path}</p>
    """

# Vulnerability 7: Weak Authentication
@app.route('/admin')
def admin():
    if request.args.get('admin') == 'true':
        return "<h1>Admin Panel</h1><p>Welcome, administrator!</p><p>User database: admin, password123</p>"
    return "<h1>Access Denied</h1><p>Admin access required</p>"

# Vulnerability 8: Path Traversal
@app.route('/file')
def file():
    filename = request.args.get('file', 'index.txt')
    # Intentionally vulnerable path traversal
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"<h1>File Contents</h1><pre>{content}</pre>"
    except Exception as e:
        return f"<h1>Error</h1><p>Could not read file: {str(e)}</p>"

# Home page with links to vulnerable endpoints
@app.route('/')
def index():
    return """
    <h1>🚨 Intentionally Vulnerable Web Application 🚨</h1>
    <p><strong>For Educational/Testing Purposes Only!</strong></p>
    
    <h2>Vulnerable Endpoints:</h2>
    <ul>
        <li><a href="/search?q=test">SQL Injection</a> - Try: <code>/search?q=' OR '1'='1</code></li>
        <li><a href="/ping?host=localhost">Command Injection</a> - Try: <code>/ping?host=localhost; ls</code></li>
        <li><a href="/comment">XSS (Cross-Site Scripting)</a> - Try: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
        <li><a href="/data?data=dGVzdA==">Unsafe Deserialization</a></li>
        <li><a href="/debug">Information Disclosure</a></li>
        <li><a href="/admin?admin=true">Weak Authentication</a></li>
        <li><a href="/file?file=../../../etc/passwd">Path Traversal</a></li>
    </ul>
    
    <h2>OWASP ZAP DAST Testing:</h2>
    <p>This application is designed to be scanned by OWASP ZAP for dynamic security testing.</p>
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
