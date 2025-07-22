# Personal Password Manager
# A secure, simple password manager with encryption

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
import sqlite3
import hashlib
from cryptography.fernet import Fernet
import os
import csv
from datetime import datetime
import io

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Generate encryption key (store this securely in production)
def get_or_create_key():
    key_file = 'encryption.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        return key

ENCRYPTION_KEY = get_or_create_key()
cipher = Fernet(ENCRYPTION_KEY)

# Database setup
def init_db():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    
    # Admin user table
    c.execute('''CREATE TABLE IF NOT EXISTS admin (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL)''')
    
    # Passwords table
    c.execute('''CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    platform TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create default admin user (username: admin, password: admin123)
    admin_hash = hashlib.sha256('Raj12&Lak61'.encode()).hexdigest()
    c.execute('INSERT OR IGNORE INTO admin (username, password_hash) VALUES (?, ?)', 
                ('RKchauhan16', admin_hash))
    
    conn.commit()
    conn.close()

# Helper functions
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

def get_db_connection():
    conn = sqlite3.connect('passwords.db')
    conn.row_factory = sqlite3.Row
    return conn

# Routes
@app.route('/')
def index():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = get_db_connection()
        admin = conn.execute('SELECT * FROM admin WHERE username = ? AND password_hash = ?',
                            (username, password_hash)).fetchone()
        conn.close()
        
        if admin:
            session['logged_in'] = True
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    search = request.args.get('search', '')
    conn = get_db_connection()
    
    if search:
        passwords = conn.execute('''SELECT * FROM passwords 
                                    WHERE platform LIKE ? OR username LIKE ?
                                    ORDER BY platform''', 
                                (f'%{search}%', f'%{search}%')).fetchall()
    else:
        passwords = conn.execute('SELECT * FROM passwords ORDER BY platform').fetchall()
    
    conn.close()
    
    # Decrypt passwords for display
    decrypted_passwords = []
    for pwd in passwords:
        decrypted_pwd = dict(pwd)
        decrypted_pwd['password'] = decrypt_password(pwd['password'])
        decrypted_passwords.append(decrypted_pwd)
    
    return render_template('dashboard.html', passwords=decrypted_passwords, search=search)

@app.route('/add', methods=['GET', 'POST'])
def add_password():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        platform = request.form['platform']
        username = request.form['username']
        password = request.form['password']
        
        if platform and username and password:
            encrypted_password = encrypt_password(password)
            
            conn = get_db_connection()
            conn.execute('''INSERT INTO passwords (platform, username, password) 
                            VALUES (?, ?, ?)''', (platform, username, encrypted_password))
            conn.commit()
            conn.close()
            
            flash('Password added successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('All fields are required!', 'error')
    
    return render_template('add_password.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_password(id):
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        platform = request.form['platform']
        username = request.form['username']
        password = request.form['password']
        
        if platform and username and password:
            encrypted_password = encrypt_password(password)
            
            conn.execute('''UPDATE passwords 
                            SET platform = ?, username = ?, password = ?, 
                                updated_date = CURRENT_TIMESTAMP 
                            WHERE id = ?''', 
                        (platform, username, encrypted_password, id))
            conn.commit()
            conn.close()
            
            flash('Password updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('All fields are required!', 'error')
    
    password_entry = conn.execute('SELECT * FROM passwords WHERE id = ?', (id,)).fetchone()
    conn.close()
    
    if not password_entry:
        flash('Password not found!', 'error')
        return redirect(url_for('dashboard'))
    
    # Decrypt password for editing
    decrypted_entry = dict(password_entry)
    decrypted_entry['password'] = decrypt_password(password_entry['password'])
    
    return render_template('edit_password.html', password=decrypted_entry)

@app.route('/delete/<int:id>')
def delete_password(id):
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM passwords WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    flash('Password deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/export')
def export_csv():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    passwords = conn.execute('SELECT * FROM passwords ORDER BY platform').fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Platform', 'Username', 'Password', 'Created Date', 'Updated Date'])
    
    # Write data (decrypted)
    for pwd in passwords:
        decrypted_password = decrypt_password(pwd['password'])
        writer.writerow([pwd['platform'], pwd['username'], decrypted_password, 
                        pwd['created_date'], pwd['updated_date']])
    
    output.seek(0)
    
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=passwords_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    return response

if __name__ == '__main__':
    init_db()
    app.run(debug=True)