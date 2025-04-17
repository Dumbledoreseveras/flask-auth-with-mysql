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
            return redirect(url_for('admin.admin_users'))  # Corrected endpoint
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
    query = "SELECT id, name, email FROM user"  # Fetch all users
    cursor.execute(query)
    users = cursor.fetchall()
    cursor.close()
    db.close()

    if not users:
        flash("No registered users found.")

    return render_template('admin_users.html', users=users)

# Admin Edit User
@admin_bp.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    if 'admin_id' not in session:
        flash("Please log in as admin.")
        return redirect(url_for('admin.admin_login'))

    db = get_db()
    cursor = db.cursor(dictionary=True)

    if request.method == 'POST':
        # Get updated user details from the form
        name = request.form['name']
        email = request.form['email']
        bio = request.form['bio']

        # Update the user in the database
        query = "UPDATE user SET name = %s, email = %s, bio = %s WHERE id = %s"
        cursor.execute(query, (name, email, bio, user_id))
        db.commit()
        cursor.close()
        db.close()

        flash("User updated successfully.")
        return redirect(url_for('admin.admin_users'))

    # Fetch the user's current details for the edit form
    query = "SELECT id, name, email, bio FROM user WHERE id = %s"
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    db.close()

    if not user:
        flash("User not found.")
        return redirect(url_for('admin.admin_users'))

    return render_template('admin_edit_user.html', user=user)

# Admin Delete User
@admin_bp.route('/admin/users/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'admin_id' not in session:
        flash("Please log in as admin.")
        return redirect(url_for('admin.admin_login'))

    db = get_db()
    cursor = db.cursor()

    # Delete the user from the database
    query = "DELETE FROM user WHERE id = %s"
    cursor.execute(query, (user_id,))
    db.commit()
    cursor.close()
    db.close()

    flash("User deleted successfully.")
    return redirect(url_for('admin.admin_users'))

# Admin View User Details
@admin_bp.route('/admin/users/view/<int:user_id>')
def admin_view_user(user_id):
    if 'admin_id' not in session:
        flash("Please log in as admin.")
        return redirect(url_for('admin.admin_login'))

    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Fetch user details, including bio
    query = "SELECT id, name, email, bio FROM user WHERE id = %s"
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    db.close()

    if not user:
        flash("User not found.")
        return redirect(url_for('admin.admin_users'))

    return render_template('admin_view_user.html', user=user)

# Admin Add New User
@admin_bp.route('/admin/users/add', methods=['GET', 'POST'])
def admin_add_user():
    if 'admin_id' not in session:
        flash("Please log in as admin.")
        return redirect(url_for('admin.admin_login'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = bcrypt.hashpw(request.form['password'].encode(), bcrypt.gensalt())

        db = get_db()
        cursor = db.cursor()
        query = "INSERT INTO user (name, email, password) VALUES (%s, %s, %s)"
        cursor.execute(query, (name, email, password.decode()))
        db.commit()
        cursor.close()
        db.close()

        flash("User added successfully.")
        return redirect(url_for('admin.admin_users'))

    return render_template('admin_add_user.html')
