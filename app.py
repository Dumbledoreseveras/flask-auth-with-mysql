from flask import Flask, render_template, redirect, url_for, session, flash, request
# you can store information specific to a user for the duration of a session
#url_for: is a function used to dynamically generate URLs for a specific route or endpoint in your application
# import mysql.connector 
from flask_wtf import FlaskForm #pip install flask-wtf and pip show flask-wtf then it will execute
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
# StringField: It is used to accept text input from the user, such as names, email addresses, or other short text data.
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt  # pip istall bcrypt and pip show bcrypt then it will execute
# pip install email-validator and pip show email-validator for email validation
from admin import admin_bp
from db import get_db


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.register_blueprint(admin_bp)

#  Database connection
# def get_db():
#     return mysql.connector.connect(
#         host = 'localhost',
#         user = 'root',
#         password = 'asish@2002#',
#         database = 'mydatabases'
#     )

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()]) # DataRequired(): ensures that the field is not left empty. if the field is empty, the form submission will faill and generate messege
    email = StringField("Email", validators=[DataRequired(), Email()])  # Email(): validates that the input is properly formatted amail address
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        db = get_db()
        cursor = db.cursor()
        query = "SELECT * FROM user WHERE email = %s"
        cursor.execute(query, (field.data,))
        user = cursor.fetchone()
        cursor.close()
        db.close()
        if user:
            raise ValidationError('Email Already Exists')
        
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])  
    password = PasswordField("Password", validators=[DataRequired()])  
    submit = SubmitField("Login")

class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    bio = TextAreaField("Bio")
    submit = SubmitField("Save")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register_data():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        db = get_db()
        cursor = db.cursor()
        query = "INSERT INTO user(name, email, password) VALUES (%s, %s, %s)"
        cursor.execute(query, (name, email, hashed_password))
        db.commit()
        cursor.close()
        db.close()
        
        return redirect(url_for('login_data'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login_data():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        db = get_db()
        cursor = db.cursor()
        query = "SELECT * FROM user WHERE email = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()
        cursor.close()
        db.close()
        
        if user:
            # Handle password checking properly
            stored_password = user[3]
            if isinstance(stored_password, str):
                stored_password = stored_password.encode('utf-8')
            
            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                session['user_id'] = user[0]
                return redirect(url_for('dashboard'))
            
        flash("Login failed. Please check your email and password")
        return redirect(url_for('login_data'))
        
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login_data'))
    
    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor(dictionary=True)  # Use dictionary cursor for named fields
    query = "SELECT * FROM user WHERE id = %s"
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    db.close()
    
    if user:
        return render_template('updated_dashboard.html', user=user)
    
    return redirect(url_for('login_data'))

@app.route('/logout')
def logout():
    if 'user_id' in session:
        session.pop('user_id', None)
        flash("You have been logged out successfully.")
    return redirect(url_for('login_data'))

@app.route('/users')
def list_users():
    if 'user_id' not in session:
        flash("Please login first")
        return redirect(url_for('login_data'))
    
    user_id = session['user_id']  # Get the logged-in user's ID
    db = get_db()
    cursor = db.cursor(dictionary=True)
    query = "SELECT id, name, email FROM user WHERE id = %s"
    cursor.execute(query, (user_id,))  # Fetch only the logged-in user's data
    users = cursor.fetchall()
    cursor.close()
    db.close()
    
    return render_template('users.html', users=users)

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session:
        flash("Please login first")
        return redirect(url_for('login_data'))
    
    if session['user_id'] != user_id:
        flash("You can only edit your own profile")
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    # First check if bio column exists
    try:
        cursor.execute("SHOW COLUMNS FROM user LIKE 'bio'")
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE user ADD COLUMN bio TEXT")
            db.commit()
    except:
        pass  # If error, continue anyway
    
    # Get user data
    query = "SELECT * FROM user WHERE id = %s"
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    
    if not user:
        db.close()
        flash("User not found")
        return redirect(url_for('dashboard'))
    
    form = UserForm()
    
    if request.method == 'GET':
        form.name.data = user['name']
        form.email.data = user['email']
        if 'bio' in user and user['bio']:
            form.bio.data = user['bio']
    
    if form.validate_on_submit():
        cursor = db.cursor()
        query = "UPDATE user SET name = %s, email = %s, bio = %s WHERE id = %s"
        cursor.execute(query, (form.name.data, form.email.data, form.bio.data, user_id))
        db.commit()
        cursor.close()
        db.close()
        
        flash("Profile updated successfully!")
        return redirect(url_for('view_user', user_id=user_id))
    
    db.close()
    return render_template('edit_user.html', form=form, user=user)

@app.route('/users/<int:user_id>')
def view_user(user_id):
    if 'user_id' not in session:
        flash("Please login first")
        return redirect(url_for('login_data'))
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    query = "SELECT * FROM user WHERE id = %s"
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    db.close()
    
    if not user:
        flash("User not found")
        return redirect(url_for('list_users'))
    
    # Remove password from the user data
    if 'password' in user:
        del user['password']
    
    return render_template('view_user.html', user=user)

@app.route('/users/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session:
        flash("Please login first")
        return redirect(url_for('login_data'))
    
    if session['user_id'] != user_id:
        flash("You can only delete your own account")
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    query = "DELETE FROM user WHERE id = %s"
    cursor.execute(query, (user_id,))
    db.commit()
    cursor.close()
    db.close()
    
    if session['user_id'] == user_id:
        session.pop('user_id', None)
        flash("Your account has been deleted successfully.")
        return redirect(url_for('index'))
    
    flash("User deleted successfully")
    return redirect(url_for('list_users'))


@app.route('/users/add', methods=['GET', 'POST'])
def add_user():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        db = get_db()
        cursor = db.cursor()
        query = "INSERT INTO user (name, email, password) VALUES (%s, %s, %s)"
        cursor.execute(query, (name, email, hashed_password))
        db.commit()
        cursor.close()
        db.close()
        
        flash("User added successfully!")
        return redirect(url_for('list_users'))
    
    return render_template('add_user.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)