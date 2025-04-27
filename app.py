from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_wtf import CSRFProtect
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
from config import config

# Models:
from models.ModelUser import ModelUser

# Entities
from models.entities.User import User

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Asegúrate de configurar una clave secreta segura

# Configuración de seguridad y base de datos
csrf = CSRFProtect(app)
db = MySQL(app)
login_manager_app = LoginManager(app)
login_manager_app.login_view = 'login'  # Define la vista de login por defecto

# Productos de ejemplo (deberías mover esto a una base de datos)
PRODUCTOS = {
    'med1': {'id': 'med1', 'nombre': 'Paracetamol', 'precio': 5.99, 'categoria': 'analgesicos', 'imagen': 'paracetamol.jpg'},
    'med2': {'id': 'med2', 'nombre': 'Ibuprofeno', 'precio': 7.50, 'categoria': 'analgesicos', 'imagen': 'ibuprofeno.jpg'},
    'med3': {'id': 'med3', 'nombre': 'Amoxicilina', 'precio': 12.75, 'categoria': 'antibioticos', 'imagen': 'amoxicilina.jpg'},
    'med4': {'id': 'med4', 'nombre': 'Diazepam', 'precio': 15.25, 'categoria': 'psicotropicos', 'imagen': 'diazepam.jpg'},
    'med5': {'id': 'med5', 'nombre': 'Omeprazol', 'precio': 8.99, 'categoria': 'medicamentos', 'imagen': 'omeprazol.jpg'},
    'med6': {'id': 'med6', 'nombre': 'Loratadina', 'precio': 6.50, 'categoria': 'medicamentos', 'imagen': 'loratadina.jpg'},
}

@login_manager_app.user_loader
def load_user(user_id):
    return ModelUser.get_by_id(db, user_id)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cursor = db.connection.cursor()
        cursor.execute("SELECT id, fullname, username, password, role FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[3], password):
            user_obj = User(user[0], user[2], user[3], user[4])  
            login_user(user_obj)

            if user[4] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('home'))

        flash("Usuario o contraseña incorrectos.")
        return redirect(url_for('login'))
    
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('carrito', None)  # Limpiar el carrito al cerrar sesión
    flash('Has cerrado sesión correctamente.')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'cliente')  

        cursor = db.connection.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash("Este usuario ya existe.")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        cursor.execute("INSERT INTO users (fullname, username, password, role) VALUES (%s, %s, %s, %s)", 
                    (fullname, username, hashed_password, role))
        db.connection.commit()
        cursor.close()

        flash("Usuario creado exitosamente.")
        return redirect(url_for('login'))
    
    return render_template('auth/register.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Acceso denegado.")
        return redirect(url_for('home'))

    return render_template('admin/admin_dashboard.html')

@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash("Acceso denegado.")
        return redirect(url_for('home'))

    cursor = db.connection.cursor()
    cursor.execute("SELECT id, fullname, username, role FROM users")
    users = cursor.fetchall()
    cursor.close()
    
    return render_template('users/users.html', users=users)

@app.route('/delete_user/<int:id>')
@login_required
def delete_user(id):
    if current_user.role != 'admin':
        flash("Acceso denegado.")
        return redirect(url_for('users'))

    cursor = db.connection.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s", (id,))
    db.connection.commit()
    cursor.close()

    flash("Usuario eliminado correctamente.")
    return redirect(url_for('users'))

# ===========================================
# Rutas para el carrito de compras
# ===========================================

@app.route('/agregar_al_carrito', methods=['POST'])
@login_required
def agregar_al_carrito():
    if request.method == 'POST':
        producto_id = request.form.get('producto_id')
        cantidad = int(request.form.get('cantidad', 1))
        
        if producto_id not in PRODUCTOS:
            flash('Producto no encontrado', 'error')
            return redirect(url_for('home'))
        
        # Inicializar carrito si no existe
        if 'carrito' not in session:
            session['carrito'] = {}
        
        # Agregar o actualizar producto en el carrito
        if producto_id in session['carrito']:
            session['carrito'][producto_id]['cantidad'] += cantidad
        else:
            session['carrito'][producto_id] = {
                'id': producto_id,
                'nombre': PRODUCTOS[producto_id]['nombre'],
                'precio': PRODUCTOS[producto_id]['precio'],
                'cantidad': cantidad,
                'imagen': PRODUCTOS[producto_id]['imagen']
            }
        
        session.modified = True
        flash('Producto agregado al carrito', 'success')
        return redirect(request.referrer or url_for('home'))

@app.route('/eliminar_del_carrito/<string:producto_id>')
@login_required
def eliminar_del_carrito(producto_id):
    if 'carrito' in session and producto_id in session['carrito']:
        del session['carrito'][producto_id]
        session.modified = True
        flash('Producto eliminado del carrito', 'success')
    return redirect(url_for('ver_carrito'))

@app.route('/actualizar_carrito', methods=['POST'])
@login_required
def actualizar_carrito():
    if 'carrito' in session:
        for producto_id, item in session['carrito'].items():
            nueva_cantidad = int(request.form.get(f'cantidad_{producto_id}', 1))
            if nueva_cantidad > 0:
                session['carrito'][producto_id]['cantidad'] = nueva_cantidad
            else:
                del session['carrito'][producto_id]
        session.modified = True
        flash('Carrito actualizado', 'success')
    return redirect(url_for('ver_carrito'))

@app.route('/carrito')
@login_required
def ver_carrito():
    carrito = session.get('carrito', {})
    total = sum(item['precio'] * item['cantidad'] for item in carrito.values())
    return render_template('carrito.html', carrito=carrito, total=total)

@app.route('/vaciar_carrito')
@login_required
def vaciar_carrito():
    if 'carrito' in session:
        session.pop('carrito')
        flash('Carrito vaciado', 'success')
    return redirect(url_for('ver_carrito'))

@app.route('/checkout')
@login_required
def checkout():
    carrito = session.get('carrito', {})
    if not carrito:
        flash('Tu carrito está vacío', 'error')
        return redirect(url_for('ver_carrito'))
    
    total = sum(item['precio'] * item['cantidad'] for item in carrito.values())
    return render_template('checkout.html', carrito=carrito, total=total)

@app.route('/procesar_pedido', methods=['POST'])
@login_required
def procesar_pedido():
    if 'carrito' not in session or not session['carrito']:
        flash('No hay productos en el carrito', 'error')
        return redirect(url_for('ver_carrito'))
    
    try:
        cursor = db.connection.cursor()
        total = sum(item['precio'] * item['cantidad'] for item in session['carrito'].values())
        
        # Insertar pedido
        cursor.execute(
            "INSERT INTO pedidos (user_id, total, estado) VALUES (%s, %s, %s)",
            (current_user.id, total, 'pendiente')
        )
        pedido_id = cursor.lastrowid
        
        # Insertar detalles del pedido
        for producto_id, item in session['carrito'].items():
            cursor.execute(
                "INSERT INTO detalles_pedido (pedido_id, producto_id, cantidad, precio_unitario) VALUES (%s, %s, %s, %s)",
                (pedido_id, producto_id, item['cantidad'], item['precio'])
            )
        
        db.connection.commit()
        cursor.close()
        
        # Vaciar carrito después del pedido exitoso
        session.pop('carrito')
        
        flash('Pedido realizado con éxito! Número de pedido: #' + str(pedido_id), 'success')
        return redirect(url_for('home'))
    
    except Exception as e:
        db.connection.rollback()
        flash('Error al procesar el pedido: ' + str(e), 'error')
        return redirect(url_for('checkout'))

# ===========================================
# Rutas para productos y categorías
# ===========================================

@app.route('/home')
@login_required
def home():
    # Obtener 4 productos destacados
    productos_destacados = [
        PRODUCTOS['med1'], 
        PRODUCTOS['med2'], 
        PRODUCTOS['med5'], 
        PRODUCTOS['med6']
    ]
    return render_template('home.html', productos_destacados=productos_destacados)

@app.route('/medicamentos')
@login_required
def medicamentos():
    productos = [p for p in PRODUCTOS.values() if p['categoria'] == 'medicamentos']
    return render_template('medicamentos.html', productos=productos)

@app.route('/edit_medicamentos', methods=['POST'])
@login_required
def edit_medicamentos():
    if current_user.role != 'admin':
        flash("Acceso denegado.")
        return redirect(url_for('medicamentos'))

    flash("Medicamento editado correctamente.")
    return redirect(url_for('medicamentos'))

@app.route('/analgesicos')
@login_required
def analgesicos():
    productos = [p for p in PRODUCTOS.values() if p['categoria'] == 'analgesicos']
    return render_template('analgesicos.html', productos=productos)

@app.route('/edit_analgesicos', methods=['POST'])
@login_required
def edit_analgesicos():
    if current_user.role != 'admin':
        flash("Acceso denegado.")
        return redirect(url_for('analgesicos'))

    flash("Analgésico editado correctamente.")
    return redirect(url_for('analgesicos'))

@app.route('/psicotropicos')
@login_required
def psicotropicos():
    productos = [p for p in PRODUCTOS.values() if p['categoria'] == 'psicotropicos']
    return render_template('psicotropicos.html', productos=productos)

@app.route('/edit_psicotropicos', methods=['POST'])
@login_required
def edit_psicotropicos():
    if current_user.role != 'admin':
        flash("Acceso denegado.")
        return redirect(url_for('psicotropicos'))

    flash("Psicotrópico editado correctamente.")
    return redirect(url_for('psicotropicos'))

@app.route('/antibioticos')
@login_required
def antibioticos():
    productos = [p for p in PRODUCTOS.values() if p['categoria'] == 'antibioticos']
    return render_template('antibioticos.html', productos=productos)

@app.route('/edit_antibioticos', methods=['POST'])
@login_required
def edit_antibioticos():
    if current_user.role != 'admin':
        flash("Acceso denegado.")
        return redirect(url_for('antibioticos'))

    flash("Antibiótico editado correctamente.")
    return redirect(url_for('antibioticos'))

@app.route('/eventos')
@login_required
def eventos():
    return render_template('eventos.html')

@app.route('/edit_eventos', methods=['POST'])
@login_required
def edit_eventos():
    if current_user.role != 'admin':
        flash("Acceso denegado.")
        return redirect(url_for('eventos'))

    flash("Evento editado correctamente.")
    return redirect(url_for('eventos'))

@app.route('/contacto', methods=['GET', 'POST'])
@login_required
def contacto():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        subject = request.form['subject']
        message = request.form['message']
        
        # Aquí podrías guardar el mensaje en la base de datos
        flash('Tu mensaje ha sido enviado. Nos pondremos en contacto contigo pronto.', 'success')
        return redirect(url_for('contacto'))
    
    return render_template('contacto.html')

@app.route('/edit_contacto', methods=['POST'])
@login_required
def edit_contacto():
    if current_user.role != 'admin':
        flash("Acceso denegado.")
        return redirect(url_for('contacto'))

    flash("Información de contacto actualizada.")
    return redirect(url_for('contacto'))

# ===========================================
# Manejo de errores
# ===========================================

@app.errorhandler(401)
def status_401(error):
    flash("Acceso no autorizado.")
    return redirect(url_for('login'))

@app.errorhandler(404)
def status_404(error):
    return render_template('errors/404.html'), 404

if __name__ == '__main__':
    app.config.from_object(config['development'])
    csrf.init_app(app)
    app.run(debug=True)