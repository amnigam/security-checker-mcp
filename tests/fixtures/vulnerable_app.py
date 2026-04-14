"""Vulnerable Flask Application — TEST FIXTURE ONLY.

Contains deliberate security violations for testing the security checker.
DO NOT deploy this code.
"""

import hashlib
import os
import pickle
import subprocess

from flask import Flask, request, session, redirect, make_response

app = Flask(__name__)
app.secret_key = "super_secret_key_12345"  # CR-05.1: Hardcoded secret
app.config["DEBUG"] = True  # EL-01.1: Debug mode enabled

# AU-01.1: Password hashed with MD5 (PROHIBITED)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# AU-01.1: SHA1 also prohibited
def hash_password_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()

# IV-05.1: SQL injection via string concatenation
def get_user(username):
    import sqlite3
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()

# IV-06.1: Command injection via shell=True
def run_diagnostic(hostname):
    result = subprocess.call(f"ping -c 1 {hostname}", shell=True)
    return result

# SM-01.1: Session ID using insecure random
import random
def generate_session_id():
    return str(random.randint(100000, 999999))

# AZ-03.1: IDOR - no authorization check
@app.route("/api/user/<int:user_id>")
def get_user_profile(user_id):
    import sqlite3
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return str(cursor.fetchone())

# IV-09.1: Unsafe deserialization
@app.route("/api/import", methods=["POST"])
def import_data():
    data = request.get_data()
    obj = pickle.loads(data)  # Unsafe deserialization
    return str(obj)

# SM-04.1, SM-05.1: Insecure cookie settings
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    hashed = hash_password(password)
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie("session_id", generate_session_id(),
                    secure=False, httponly=False)  # Insecure cookie
    return resp

# EL-04.1: Logging sensitive data
import logging
logger = logging.getLogger(__name__)

@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    logger.info(f"User registered: {username} with password: {password}")
    return "Registered"

# CR-07.1: Disabled certificate verification
import requests as http_requests
def fetch_external_data(url):
    response = http_requests.get(url, verify=False)
    return response.text

# XS-02.1: DOM-based XSS via innerHTML equivalent
@app.route("/search")
def search():
    query = request.args.get("q", "")
    return f"<html><body>Results for: {query}</body></html>"  # XS-03.1: Reflected XSS

# AU-07.1: Different error messages for invalid user vs password
@app.route("/auth", methods=["POST"])
def authenticate():
    username = request.form.get("username")
    password = request.form.get("password")
    user = get_user(username)
    if not user:
        return "User not found", 401  # Reveals account existence
    if user[2] != hash_password(password):
        return "Wrong password", 401  # Different message
    return "OK"

# Database credentials hardcoded (CR-05.1)
DB_URL = "postgresql://admin:p@ssw0rd123@prod-db.internal:5432/maindb"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
