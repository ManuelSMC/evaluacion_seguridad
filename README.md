# 🔐 Secure Application Development Project with Flask and JWT

This project is a web application developed using **Flask** that implements secure authentication with **JSON Web Tokens (JWT)**. It focuses on best practices recommended by **OWASP** to protect routes and manage users securely.

---

## Features

- JWT-based authentication
- Secure user registration and login
- Password hashing with bcrypt
- Protected routes using decorators
- Session and token expiration handling
- User CRUD operations
- Product CRUD operations

--

## Version python
3.12.2

## Dependences to install
See requirements.txt

--

## Steps to run
## 1. Create Environment
python -m venv "name environment"
## 2. Activate venv
venv\Scripts\activate.bat (on Windows)
## 3. Install dependences
pip install -r requirements.txt
## 4. python "file name"
example:
python app_vulnerable.py