# Flask Authentication with MySQL

This project is a Flask web application that provides user authentication and management functionalities using a MySQL database. It allows users to register, log in, and manage their profiles, while also providing an admin interface to view all users.

## Project Structure

```
flask-auth-with-mysql
├── templates
│   ├── add_user.html
│   ├── edit_user.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── updated_dashboard.html
│   ├── users.html
│   └── view_user.html
├── app.py
├── admin.py
└── README.md
```

## Requirements

- Python 3.x
- Flask
- Flask-WTF
- MySQL Connector
- Bcrypt
- Email Validator

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd flask-auth-with-mysql
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

3. Set up your MySQL database:
   - Create a database named `mydatabases`.
   - Create a table named `user` with the following fields:
     - `id` (INT, Primary Key, Auto Increment)
     - `name` (VARCHAR)
     - `email` (VARCHAR, Unique)
     - `password` (VARCHAR)
     - `bio` (TEXT, Optional)

## Usage

1. Run the application:
   ```
   python app.py
   ```

2. Access the application in your web browser at `http://127.0.0.1:5000`.

## Features

- User Registration: Users can create an account by providing their name, email, and password.
- User Login: Registered users can log in to their accounts.
- User Dashboard: After logging in, users can view and edit their profiles.
- Admin Functionality: Admins can view all registered users in the application.

## Admin Functionality

The `admin.py` file contains the routes and logic for the admin to view all users. This functionality is restricted to users with admin privileges.

## License

This project is licensed under the MIT License.