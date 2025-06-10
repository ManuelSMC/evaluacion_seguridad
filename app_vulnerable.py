from flask import Flask, request, jsonify
from functools import wraps
import sqlite3
import jwt
import datetime
import re
from werkzeug.security import generate_password_hash, check_password_hash
from typing import Tuple, Optional, Dict, Any

app = Flask(__name__)
app.config['DEBUG'] = True
# Clave secreta para JWT, se debe mantener en secreto y no exponer en el código fuente, pero para pruebas se queda así.
SECRET_KEY = "a8f3c9d2f021ae6b8b76935b8e7f89ad28d76f9d29e3a1cf21e8b2c91566f51a"

# Funciones de validación (USUARIOS)
def validate_email(email: str) -> bool:
    """Valida formato de correo electrónico."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(email and re.match(email_regex, email))

def validate_username(username: str) -> bool:
    """Valida longitud y caracteres del nombre de usuario."""
    return bool(username and 3 <= len(username) <= 50 and re.match(r'^[a-zA-Z0-9_]+$', username))

def validate_password(password: str) -> bool:
    """Valida que la contraseña tenga al menos 8 caracteres."""
    return bool(password and len(password) >= 8)

def validate_date(date_str: str) -> bool:
    """Valida formato de fecha (YYYY-MM-DD)."""
    try:
        datetime.datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False

# Funciones de validación (PRODUCTOS)
def validate_product_name(name: str) -> bool:
    """Valida el nombre del producto (3-100 caracteres, alfanumérico y espacios)."""
    return bool(name and 3 <= len(name) <= 100 and re.match(r'^[a-zA-Z0-9\s]+$', name))

def validate_product_description(description: str) -> bool:
    """Valida la descripción del producto (10-500 caracteres)."""
    return bool(description and 10 <= len(description) <= 500)

def validate_price(price: Any) -> bool:
    """Valida que el precio sea un número positivo con hasta 2 decimales."""
    try:
        price = float(price)
        return price > 0 and round(price, 2) == price
    except (ValueError, TypeError):
        return False


# Conexión a la base de datos
def get_db_connection() -> sqlite3.Connection:
    """Crea conexión a la base de datos con row_factory."""
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

# Inicialización de la base de datos
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            birth_date DATE NOT NULL,
            status INTEGER NOT NULL DEFAULT 1,
            secret_question TEXT NOT NULL,
            secret_answer TEXT NOT NULL,
            permission TEXT NOT NULL DEFAULT 'user'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            creation_date DATE NOT NULL,
            arrival_price DECIMAL(10, 2) NOT NULL,
            retail_price DECIMAL(10, 2) NOT NULL,
            wholesale_price DECIMAL(10, 2) NOT NULL
        )
    """)


# Insertar usuarios de prueba con contraseñas hasheadas
    users = [
        ('username1', 'Hola.123', 'username1@gmail.com', '2002-06-03', 1, '¿Cuál es tu color favorito?', 'Rojo', 'super_admin'),
        ('username2', 'Hola.123', 'username2@gmail.com', '2003-06-03', 1, '¿Cuál es tu fruta favorita?', 'Mango', 'user'),
        ('username3', 'Hola.123', 'username3@gmail.com', '2004-06-03', 1, '¿Cómo se llama tu mejor amigo?', 'Manuel', 'user'),
        ('username4', 'Hola.123', 'username4@gmail.com', '2005-06-03', 1, '¿Cuál es tu comida favorita?', 'Mole', 'user')
    ]
    
    for user in users:
        username, password, email, birth_date, status, secret_question, secret_answer, permission = user
        hashed_password = generate_password_hash(password)
        cursor.execute(
            """INSERT INTO users (username, password, email, birth_date, status, secret_question, secret_answer, permission)
               SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = ?)""",
            (username, hashed_password, email, birth_date, status, secret_question, secret_answer, permission, username)
        )
    
    # Insertar productos de prueba
    products = [
        ('producto1', 'Descripción del producto 1', '2001-01-01', 11.11, 111.11, 100.11),
        ('producto2', 'Descripción del producto 2', '2002-02-02', 22.22, 222.22, 200.22),
        ('producto3', 'Descripción del producto 3', '2003-03-03', 33.33, 333.33, 300.33),
        ('producto4', 'Descripción del producto 4', '2004-04-04', 44.44, 444.44, 400.44)
    ]
    
    for product in products:
        cursor.execute(
            """INSERT INTO products (name, description, creation_date, arrival_price, retail_price, wholesale_price)
               SELECT ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = ?)""",
            product + (product[0],)
        )
    
    conn.commit()
    conn.close()

# ===================== DECORADOR JWT =====================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token requerido', 'status': 'error'}), 401
        try:
            if token.startswith("Bearer "):
                token = token.split(" ")[1]
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            if decoded.get('permission') != 'super_admin':
                return jsonify({'message': 'Permiso de super_admin requerido', 'status': 'error'}), 403
            request.user = decoded
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado', 'status': 'error'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido', 'status': 'error'}), 401
        return f(*args, **kwargs)
    return decorated


# ==============================================================
# ===================== APIs Para Usuarios =====================
# ==============================================================



# ===================== Ruta para obtener todos los usuarios =====================

@app.route('/users', methods=['GET'])
@token_required
def list_users():
    """Lista todos los usuarios."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, birth_date, status, permission FROM users")
        users = cursor.fetchall()
        conn.close()
        
        return jsonify({
            "status": "success",
            "users": [{
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "birth_date": user["birth_date"],
                "status": user["status"],
                "permission": user["permission"]
            } for user in users]
        }), 200
    except sqlite3.Error as e:
        return jsonify({"message": f"Error en la base de datos: {str(e)}", "status": "error"}), 500
    
    

# ===================== Ruta para obtener usuario por id =====================

@app.route('/users/<int:user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    """Obtiene información de un usuario por ID."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, birth_date, status, permission FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({"message": "Usuario no encontrado", "status": "error"}), 404
        
        return jsonify({
            "status": "success",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "birth_date": user["birth_date"],
                "status": user["status"],
                "permission": user["permission"]
            }
        }), 200
    except sqlite3.Error as e:
        return jsonify({"message": f"Error en la base de datos: {str(e)}", "status": "error"}), 500


# ===================== Login con JWT =====================

@app.route('/login', methods=['POST'])
def login():
    """Autentica usuarios y genera token JWT con 5 minutos de vida."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"message": "Usuario y contraseña son requeridos", "status": "error"}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, status, permission FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if not user or not check_password_hash(user["password"], password):
            return jsonify({"message": "Credenciales incorrectas", "status": "error"}), 401
        
        if user["status"] != 1:
            return jsonify({"message": "Usuario deshabilitado", "status": "error"}), 403
        
        payload = {
            'user_id': user["id"],
            'username': user["username"],
            'permission': user["permission"],
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

        return jsonify({
            "status": "success",
            "message": "Login exitoso",
            "token": token
        }), 200
    except sqlite3.Error as e:
        return jsonify({"message": f"Error en la base de datos: {str(e)}", "status": "error"}), 500
    


# Acceso sin control -A01: Broken Access Control

@app.route('/admin/data', methods=['GET'])
@token_required
def admin_data():
    """Ruta protegida para datos administrativos."""
    return jsonify({
        "status": "success",
        "data": "Datos confidenciales del administrador"
    }), 200



# ===================== Ruta para registrar usuarios =====================

@app.route('/register_user', methods=['POST'])
def register_user():
    """Registra un nuevo usuario."""
    data = request.get_json()
    
    required_fields = ['username', 'password', 'email', 'birth_date', 'secret_question', 'secret_answer']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Todos los campos son requeridos", "status": "error"}), 400
    
    username = data['username']
    password = data['password']
    email = data['email']
    birth_date = data['birth_date']
    secret_question = data['secret_question']
    secret_answer = data['secret_answer']
    permission = data.get('permission', 'user')
    
    if not validate_username(username):
        return jsonify({"message": "Nombre de usuario inválido (3-50 caracteres, solo letras, números y guiones bajos)", "status": "error"}), 400
    if not validate_password(password):
        return jsonify({"message": "La contraseña debe tener al menos 8 caracteres", "status": "error"}), 400
    if not validate_email(email):
        return jsonify({"message": "Correo electrónico inválido", "status": "error"}), 400
    if not validate_date(birth_date):
        return jsonify({"message": "Formato de fecha inválido (YYYY-MM-DD)", "status": "error"}), 400
    if permission not in ['user', 'super_admin']:
        return jsonify({"message": "Permiso inválido", "status": "error"}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar si el email ya existe
        cursor.execute("SELECT 1 FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"message": "Correo electrónico ya registrado", "status": "error"}), 400
        
        # Verificar si el username ya existe
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"message": "Nombre de usuario ya registrado", "status": "error"}), 400
        
        # Hash de la contraseña
        hashed_password = generate_password_hash(password)
        
        cursor.execute(
            """INSERT INTO users (username, password, email, birth_date, status, secret_question, secret_answer, permission)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (username, hashed_password, email, birth_date, 1, secret_question, secret_answer, permission)
        )
        conn.commit()
        conn.close()
        
        return jsonify({"message": "Usuario registrado exitosamente", "status": "success"}), 201
    except sqlite3.Error as e:
        return jsonify({"message": f"Error en la base de datos: {str(e)}", "status": "error"}), 500



# ===================== Ruta para deshabilitar usuarios =====================

@app.route('/users/<int:user_id>/disable', methods=['PUT'])
@token_required
def disable_user(user_id):
    """Deshabilita un usuario."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET status = 0 WHERE id = ?", (user_id,))
        conn.commit()
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"message": "Usuario no encontrado", "status": "error"}), 404
        
        conn.close()
        return jsonify({"message": "Usuario deshabilitado correctamente", "status": "success"}), 200
    except sqlite3.Error as e:
        return jsonify({"message": f"Error en la base de datos: {str(e)}", "status": "error"}), 500
    

# ===================== Ruta para habilitar usuarios =====================

@app.route('/users/<int:user_id>/enable', methods=['PUT'])
@token_required
def enable_user(user_id):
    """Habilita un usuario."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET status = 1 WHERE id = ?", (user_id,))
        conn.commit()
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"message": "Usuario no encontrado", "status": "error"}), 404
        
        conn.close()
        return jsonify({"message": "Usuario habilitado correctamente", "status": "success"}), 200
    except sqlite3.Error as e:
        return jsonify({"message": f"Error en la base de datos: {str(e)}", "status": "error"}), 500



# ===================== Ruta para editar usuarios =====================

@app.route('/users/<int:user_id>', methods=['PUT'])
@token_required
def edit_user(user_id):
    """Edita información de un usuario."""
    data = request.get_json()
    
    required_fields = ['username', 'password', 'email', 'birth_date', 'secret_question', 'secret_answer']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Todos los campos son requeridos", "status": "error"}), 400
    
    username = data['username']
    password = data['password']
    email = data['email']
    birth_date = data['birth_date']
    secret_question = data['secret_question']
    secret_answer = data['secret_answer']
    permission = data.get('permission', 'user')
    
    # Validaciones
    if not validate_username(username):
        return jsonify({"message": "Nombre de usuario inválido (3-50 caracteres, solo letras, números y guiones bajos)", "status": "error"}), 400
    if not validate_password(password):
        return jsonify({"message": "La contraseña debe tener al menos 8 caracteres", "status": "error"}), 400
    if not validate_email(email):
        return jsonify({"message": "Correo electrónico inválido", "status": "error"}), 400
    if not validate_date(birth_date):
        return jsonify({"message": "Formato de fecha inválido (YYYY-MM-DD)", "status": "error"}), 400
    if permission not in ['user', 'super_admin']:
        return jsonify({"message": "Permiso inválido", "status": "error"}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar si el email ya existe para otro usuario
        cursor.execute("SELECT 1 FROM users WHERE email = ? AND id != ?", (email, user_id))
        if cursor.fetchone():
            conn.close()
            return jsonify({"message": "Correo electrónico ya registrado", "status": "error"}), 400
        
        # Verificar si el username ya existe para otro usuario
        cursor.execute("SELECT 1 FROM users WHERE username = ? AND id != ?", (username, user_id))
        if cursor.fetchone():
            conn.close()
            return jsonify({"message": "Nombre de usuario ya registrado", "status": "error"}), 400
        
        # Hash de la contraseña
        hashed_password = generate_password_hash(password)
        
        cursor.execute(
            """UPDATE users SET username = ?, password = ?, email = ?, birth_date = ?, status = ?, 
               secret_question = ?, secret_answer = ?, permission = ? WHERE id = ?""",
            (username, hashed_password, email, birth_date, 1, secret_question, secret_answer, permission, user_id)
        )
        conn.commit()
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"message": "Usuario no encontrado", "status": "error"}), 404
        
        conn.close()
        return jsonify({"message": "Usuario editado correctamente", "status": "success"}), 200
    except sqlite3.Error as e:
        return jsonify({"message": f"Error en la base de datos: {str(e)}", "status": "error"}), 500


# ===============================================================
# ===================== APIs Para Productos =====================
# ===============================================================



# ===================== Ruta para crear un nuevo producto =====================

@app.route('/products', methods=['POST'])
@token_required
def create_product():
    """Crea un nuevo producto."""
    data = request.get_json()
    
    required_fields = ['name', 'description', 'creation_date', 'arrival_price', 'retail_price', 'wholesale_price']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Todos los campos son requeridos", "status": "error"}), 400
    
    name = data['name']
    description = data['description']
    creation_date = data['creation_date']
    arrival_price = data['arrival_price']
    retail_price = data['retail_price']
    wholesale_price = data['wholesale_price']
    
    # Validaciones
    if not validate_product_name(name):
        return jsonify({"message": "Nombre del producto inválido (3-100 caracteres, solo letras, números y espacios)", "status": "error"}), 400
    if not validate_product_description(description):
        return jsonify({"message": "Descripción inválida (10-500 caracteres)", "status": "error"}), 400
    if not validate_date(creation_date):
        return jsonify({"message": "Formato de fecha inválido (YYYY-MM-DD)", "status": "error"}), 400
    if not validate_price(arrival_price):
        return jsonify({"message": "Precio de llegada inválido (número positivo con hasta 2 decimales)", "status": "error"}), 400
    if not validate_price(retail_price):
        return jsonify({"message": "Precio minorista inválido (número positivo con hasta 2 decimales)", "status": "error"}), 400
    if not validate_price(wholesale_price):
        return jsonify({"message": "Precio mayorista inválido (número positivo con hasta 2 decimales)", "status": "error"}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar si el nombre del producto ya existe
        cursor.execute("SELECT 1 FROM products WHERE name = ?", (name,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"message": "Nombre del producto ya registrado", "status": "error"}), 400
        
        cursor.execute(
            """INSERT INTO products (name, description, creation_date, arrival_price, retail_price, wholesale_price)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, description, creation_date, float(arrival_price), float(retail_price), float(wholesale_price))
        )
        product_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            "status": "success",
            "message": "Producto creado exitosamente",
            "product_id": product_id
        }), 201
    except sqlite3.Error as e:
        return jsonify({"message": f"Error en la base de datos: {str(e)}", "status": "error"}), 500



# ===================== Ruta para obtener un producto por id =====================

@app.route('/products/<int:product_id>', methods=['GET'])
@token_required
def get_product(product_id):
    """Obtiene información de un producto por ID."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        conn.close()
        
        if not product:
            return jsonify({"message": "Producto no encontrado", "status": "error"}), 404
        
        return jsonify({
            "status": "success",
            "product": {
                "id": product["id"],
                "name": product["name"],
                "description": product["description"],
                "creation_date": product["creation_date"],
                "arrival_price": float(product["arrival_price"]),
                "retail_price": float(product["retail_price"]),
                "wholesale_price": float(product["wholesale_price"])
            }
        }), 200
    except sqlite3.Error as e:
        return jsonify({"message": f"Error en la base de datos: {str(e)}", "status": "error"}), 500



# ===================== Ruta para obtener todos los productos =====================

@app.route('/products', methods=['GET'])
@token_required
def list_products():
    """Lista todos los productos."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()
        conn.close()
        
        return jsonify({
            "status": "success",
            "products": [{
                "id": product["id"],
                "name": product["name"],
                "description": product["description"],
                "creation_date": product["creation_date"],
                "arrival_price": float(product["arrival_price"]),
                "retail_price": float(product["retail_price"]),
                "wholesale_price": float(product["wholesale_price"])
            } for product in products]
        }), 200
    except sqlite3.Error as e:
        return jsonify({"message": f"Error en la base de datos: {str(e)}", "status": "error"}), 500



# ===================== Ruta para actualizar un producto =====================

@app.route('/products/<int:product_id>', methods=['PUT'])
@token_required
def update_product(product_id):
    """Actualiza información de un producto."""
    data = request.get_json()
    
    required_fields = ['name', 'description', 'creation_date', 'arrival_price', 'retail_price', 'wholesale_price']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Todos los campos son requeridos", "status": "error"}), 400
    
    name = data['name']
    description = data['description']
    creation_date = data['creation_date']
    arrival_price = data['arrival_price']
    retail_price = data['retail_price']
    wholesale_price = data['wholesale_price']
    
    # Validaciones
    if not validate_product_name(name):
        return jsonify({"message": "Nombre del producto inválido (3-100 caracteres, solo letras, números y espacios)", "status": "error"}), 400
    if not validate_product_description(description):
        return jsonify({"message": "Descripción inválida (10-500 caracteres)", "status": "error"}), 400
    if not validate_date(creation_date):
        return jsonify({"message": "Formato de fecha inválido (YYYY-MM-DD)", "status": "error"}), 400
    if not validate_price(arrival_price):
        return jsonify({"message": "Precio de llegada inválido (número positivo con hasta 2 decimales)", "status": "error"}), 400
    if not validate_price(retail_price):
        return jsonify({"message": "Precio minorista inválido (número positivo con hasta 2 decimales)", "status": "error"}), 400
    if not validate_price(wholesale_price):
        return jsonify({"message": "Precio mayorista inválido (número positivo con hasta 2 decimales)", "status": "error"}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar si el nombre del producto ya existe para otro producto
        cursor.execute("SELECT 1 FROM products WHERE name = ? AND id != ?", (name, product_id))
        if cursor.fetchone():
            conn.close()
            return jsonify({"message": "Nombre del producto ya registrado", "status": "error"}), 400
        
        cursor.execute(
            """UPDATE products SET name = ?, description = ?, creation_date = ?, arrival_price = ?, 
               retail_price = ?, wholesale_price = ? WHERE id = ?""",
            (name, description, creation_date, float(arrival_price), float(retail_price), float(wholesale_price), product_id)
        )
        conn.commit()
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"message": "Producto no encontrado", "status": "error"}), 404
        
        conn.close()
        return jsonify({"message": "Producto actualizado correctamente", "status": "success"}), 200
    except sqlite3.Error as e:
        return jsonify({"message": f"Error en la base de datos: {str(e)}", "status": "error"}), 500



# ===================== Ruta para eliminar un producto =====================

@app.route('/products/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(product_id):
    """Elimina un producto."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
        conn.commit()
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"message": "Producto no encontrado", "status": "error"}), 404
        
        conn.close()
        return jsonify({"message": "Producto eliminado correctamente", "status": "success"}), 200
    except sqlite3.Error as e:
        return jsonify({"message": f"Error en la base de datos: {str(e)}", "status": "error"}), 500



# Main

if __name__ == '__main__':
    init_db()
    app.run(debug=True)