from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from db import get_db
import bcrypt

admin_bp = Blueprint('admin', __name__, template_folder='templates')

# Admin Registration
@admin_bp.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.hashpw(request.form['password'].encode(), bcrypt.gensalt())

        db = get_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO admin (username, password) VALUES (%s, %s)", (username, password.decode()))
        db.commit()
        cursor.close()
        db.close()

        flash("Admin registered successfully. Please log in.")
        return redirect(url_for('admin.admin_login'))

    return render_template('admin_register.html')

# Admin Login
@admin_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
        admin = cursor.fetchone()
        cursor.close()
        db.close()

        if admin and bcrypt.checkpw(password.encode(), admin['password'].encode()):
            session['admin_id'] = admin['id']
            flash("Login successful.")
            return redirect(url_for('admin.admin_user'))
        else:
            flash("Invalid username or password.")

    return render_template('admin_login.html')

# Admin Logout
@admin_bp.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    flash("Logged out successfully.")
    return redirect(url_for('admin.admin_login'))

# Admin View All Registered Users
@admin_bp.route('/admin/users')
def admin_users():
    if 'admin_id' not in session:
        flash("Please log in admin.")
        return redirect(url_for('admin.admin_login'))

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id, name, email, created_at FROM user ORDER BY created_at DESC")  # Fetch users in descending order
    users = cursor.fetchall()
    cursor.close()
    db.close()

    if not users:
        flash("No registered users found.")

    return render_template('admin_users.html', users=users)
