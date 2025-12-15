
from flask import Flask, render_template, redirect, url_for, request, flash, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from sqlalchemy import text
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from functools import wraps
import os
import smtplib
from email.message import EmailMessage

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'supersecretkey')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stock.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 15
CATS_PER_PAGE = 10

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer")

    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == "admin"

    def is_staff(self):
        return self.role in ("admin", "staff")

    def is_viewer(self):
        return self.role == "viewer"


class Categoria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(150), unique=True, nullable=False)
    tipo = db.Column(db.String(50), default="informatica", nullable=False)
    icon = db.Column(db.String(200), nullable=True)
    padre_id = db.Column(db.Integer, db.ForeignKey('categoria.id'), nullable=True)

    
    padre = db.relationship('Categoria', remote_side=[id], backref='hijos', uselist=False)

    productos = db.relationship('Producto', backref='categoria', lazy='dynamic')


class Producto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(150), nullable=False)

    categoria_id = db.Column(db.Integer, db.ForeignKey('categoria.id'), nullable=False)

    stock = db.Column(db.Integer, default=0, nullable=False)
    minimo = db.Column(db.Integer, default=0, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def cantidad(self):
        return self.stock

    @cantidad.setter
    def cantidad(self, value):
        self.stock = int(value)

    def __repr__(self):
        return f"<Producto {self.nombre} (stock={self.stock})>"


class Movimiento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    producto_id = db.Column(db.Integer, db.ForeignKey('producto.id'), nullable=False)
    producto = db.relationship('Producto')

    tipo = db.Column(db.String(20))
    cantidad = db.Column(db.Integer)
    usuario = db.Column(db.String(150))
    fecha = db.Column(db.DateTime, default=datetime.utcnow)


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(150))
    accion = db.Column(db.String(500))
    fecha = db.Column(db.DateTime, default=datetime.utcnow)


def registrar_log(texto):
    usuario = current_user.username if current_user.is_authenticated else "desconocido"
    log = Log(usuario=usuario, accion=texto)
    db.session.add(log)
    db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



def crear_datos_iniciales():
    with app.app_context():
        db.create_all()

        
        try:
            conn = db.engine.connect()
            res = conn.execute(text("PRAGMA table_info(categoria)")).fetchall()
            colnames = [r[1] for r in res]
            if 'icon' not in colnames:
                conn.execute(text("ALTER TABLE categoria ADD COLUMN icon VARCHAR"))
            if 'padre_id' not in colnames:
                conn.execute(text("ALTER TABLE categoria ADD COLUMN padre_id INTEGER"))
            conn.close()
        except Exception:
            pass

        
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", role="admin")
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()

        
        if Categoria.query.count() == 0:
            inicial = [
                ("Monitores", None),
                ("Teclados", None),
                ("Notebooks", None),
                ("Computadoras", None),
                ("Accesorios", None),
                ("Impresoras", None),
            ]
            for nombre, padre in inicial:
                db.session.add(Categoria(nombre=nombre, tipo="informatica"))
            db.session.commit()


crear_datos_iniciales()



def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                return "No autorizado", 403
            return f(*args, **kwargs)
        return wrapped
    return decorator



@app.context_processor
def inyectar_fecha():
    return {"current_year": datetime.utcnow().year}



def get_serializer():
    return URLSafeTimedSerializer(app.config['SECRET_KEY'])


def generate_reset_token(user_identifier):
    s = get_serializer()
    return s.dumps(user_identifier, salt='password-reset-salt')


def verify_reset_token(token, max_age=3600):
    s = get_serializer()
    try:
        val = s.loads(token, salt='password-reset-salt', max_age=max_age)
        return val
    except (SignatureExpired, BadSignature):
        return None


def send_reset_email(to, link):
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port = int(os.environ.get('SMTP_PORT', 0)) if os.environ.get('SMTP_PORT') else None
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    email_from = os.environ.get('EMAIL_FROM', 'no-reply@example.com')

    msg = EmailMessage()
    msg['Subject'] = 'Recuperación de contraseña - Sistema de Stock'
    msg['From'] = email_from
    msg['To'] = to
    msg.set_content(f"Recuperación de contraseña:\n\n{link}\n\nSi no pediste esto, ignorá.")

    if smtp_host and smtp_port and smtp_user and smtp_pass:
        try:
            with smtplib.SMTP_SSL(smtp_host, smtp_port) as smtp:
                smtp.login(smtp_user, smtp_pass)
                smtp.send_message(msg)
            app.logger.info("Email enviado a %s", to)
            return True
        except Exception as e:
            app.logger.error("Error enviando email: %s", e)

    print(f"[DEV] Reset link for {to}: {link}")
    return False



@app.route('/')
@login_required
def index():
    q_name = request.args.get("name", "").strip()
    q_cat = request.args.get("category", "").strip()
    q_min = request.args.get("min_stock", "").strip()
    q_max = request.args.get("max_stock", "").strip()
    q_state = request.args.get("state", "").strip()

    query = Producto.query.join(Categoria)

    if q_name:
        query = query.filter(Producto.nombre.ilike(f"%{q_name}%"))

    if q_cat:
        categoria = Categoria.query.filter_by(nombre=q_cat, tipo="informatica").first()
        if categoria:
            query = query.filter(Producto.categoria_id == categoria.id)
        else:
            query = query.filter(text("1=0"))

    if q_min:
        try:
            query = query.filter(Producto.stock >= int(q_min))
        except:
            pass

    if q_max:
        try:
            query = query.filter(Producto.stock <= int(q_max))
        except:
            pass

    if q_state == "bajo":
        query = query.filter(Producto.stock <= Producto.minimo)
    elif q_state == "normal":
        query = query.filter(Producto.stock > Producto.minimo)

    productos = query.all()
    categorias = Categoria.query.filter_by(tipo="informatica", padre_id=None).order_by(Categoria.nombre).all()

    return render_template('index.html', productos=productos, categorias=categorias,
                           q_name=q_name, q_cat=q_cat, q_min=q_min, q_max=q_max, q_state=q_state)



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()
        if not user:
            flash("Usuario o contraseña incorrectos.", "danger")
            return redirect(url_for('login'))

        if user.locked_until and datetime.utcnow() < user.locked_until:
            remaining = (user.locked_until - datetime.utcnow()).seconds // 60 + 1
            flash(f"Cuenta bloqueada por intentos fallidos. Probá en {remaining} minutos.", "danger")
            return redirect(url_for('login'))

        if user.check_password(password):
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()
            login_user(user)
            registrar_log("Inicio de sesión")
            return redirect(url_for('index'))
        else:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = datetime.utcnow() + timedelta(minutes=LOCK_MINUTES)
                registrar_log(f"Cuenta bloqueada: {user.username}")
                flash(f"Demasiados intentos. Cuenta bloqueada {LOCK_MINUTES} minutos.", "danger")
            else:
                flash("Usuario o contraseña incorrectos.", "danger")
            db.session.commit()
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    registrar_log("Cierre de sesión")
    logout_user()
    return redirect(url_for('login'))



@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        user = User.query.filter_by(username=username).first()

        if not user:
            flash("Si el usuario existe, se enviará un email con instrucciones.", "info")
            return redirect(url_for('login'))

        token = generate_reset_token(user.username)
        link = url_for('reset_password', token=token, _external=True)
        send_reset_email(user.username, link)
        registrar_log(f"Solicitud recuperación: {user.username}")
        flash("Si el usuario existe, se enviará un email con instrucciones.", "info")
        return redirect(url_for('login'))
    return render_template('reset_request.html')


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    username = verify_reset_token(token, max_age=3600)
    if not username:
        flash("Token inválido o expirado.", "danger")
        return redirect(url_for('reset_request'))

    user = User.query.filter_by(username=username).first_or_404()
    if request.method == 'POST':
        nueva = request.form.get('password')
        confirmar = request.form.get('confirm')
        if not nueva or nueva != confirmar:
            flash("Contraseñas no coinciden o vacías.", "danger")
            return redirect(url_for('reset_password', token=token))
        user.set_password(nueva)
        user.failed_attempts = 0
        user.locked_until = None
        db.session.commit()
        registrar_log(f"Contraseña reiniciada: {user.username}")
        flash("Contraseña cambiada correctamente. Hacé login.", "success")
        return redirect(url_for('login'))
    return render_template('reset_password.html', username=username)



@app.route('/cambiar_contrasena', methods=['GET', 'POST'])
@login_required
def cambiar_contrasena():
    if request.method == 'POST':
        actual = request.form['actual']
        nueva = request.form['nueva']
        confirmar = request.form['confirmar']
        if not current_user.check_password(actual):
            flash("La contraseña actual no es correcta.", "danger")
            return redirect(url_for('cambiar_contrasena'))
        if nueva != confirmar:
            flash("Las contraseñas no coinciden.", "danger")
            return redirect(url_for('cambiar_contrasena'))
        current_user.set_password(nueva)
        db.session.commit()
        registrar_log("Cambió su contraseña")
        flash("Contraseña cambiada correctamente.", "success")
        return redirect(url_for('index'))
    return render_template('cambiar_contrasena.html')



@app.route('/usuarios', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def usuarios():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role') or 'viewer'
        if not username or not password:
            flash("Faltan datos", "danger")
            return redirect(url_for('usuarios'))
        if User.query.filter_by(username=username).first():
            flash("El usuario ya existe", "warning")
            return redirect(url_for('usuarios'))
        nuevo = User(username=username, role=role)
        nuevo.set_password(password)
        db.session.add(nuevo)
        db.session.commit()
        flash("Usuario creado correctamente", "success")
        return redirect(url_for('usuarios'))
    lista = User.query.all()
    return render_template('usuarios.html', usuarios=lista)


@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def editar_usuario(id):
    usuario = User.query.get_or_404(id)
    if request.method == "POST":
        usuario.username = request.form['username']
        usuario.role = request.form['role']
        db.session.commit()
        flash("Usuario actualizado", "success")
        return redirect(url_for('usuarios'))
    return render_template('editar_usuario.html', usuario=usuario)


@app.route('/eliminar_usuario/<int:user_id>')
@login_required
@roles_required('admin')
def eliminar_usuario(user_id):
    usuario = User.query.get_or_404(user_id)
    if usuario.username == "admin":
        flash("No podés eliminar al admin principal", "danger")
        return redirect(url_for('usuarios'))
    db.session.delete(usuario)
    db.session.commit()
    flash("Usuario eliminado correctamente", "success")
    return redirect(url_for('usuarios'))




@app.route('/categorias', methods=['GET', 'POST'])
@login_required
def categorias():
    if request.method == 'POST':
        if not current_user.is_admin():
            return "No autorizado", 403

        nombre = request.form.get('nombre', '').strip()
        padre_id = request.form.get('padre_id') or None

        if not nombre:
            flash("El nombre no puede estar vacío.", "danger")
            return redirect(url_for('categorias'))

        if Categoria.query.filter_by(nombre=nombre).first():
            flash("Ya existe esa categoría.", "warning")
            return redirect(url_for('categorias'))

        nueva = Categoria(nombre=nombre, tipo="informatica")

        if padre_id:
            padre = Categoria.query.get(int(padre_id))
            if padre:
                nueva.padre = padre

        db.session.add(nueva)
        db.session.commit()

        registrar_log(f"Agregó categoría: {nombre}")
        flash("Categoría agregada correctamente.", "success")
        return redirect(url_for('categorias'))

    
    q = request.args.get('q', '').strip()
    order = request.args.get('order', 'asc')

    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1

    query = Categoria.query

    if q:
        query = query.filter(Categoria.nombre.ilike(f"%{q}%"))

    if order == 'desc':
        query = query.order_by(Categoria.nombre.desc())
    else:
        query = query.order_by(Categoria.nombre.asc())

    pagination = query.paginate(page=page, per_page=CATS_PER_PAGE, error_out=False)
    categorias_page = pagination.items

    
    cantidades = {
    c.id: c.productos.count()
    for c in categorias_page
}


    return render_template(
        'categorias.html',
        categorias=categorias_page,
        pagination=pagination,
        q=q,
        order=order,
        cantidades=cantidades
    )





@app.route('/categorias/<int:id>/editar', methods=['POST'])
@login_required
@roles_required('admin')
def editar_categoria(id):
    categoria = Categoria.query.get_or_404(id)
    nuevo_nombre = request.form.get('nombre', '').strip()
    nuevo_icon = request.form.get('icon', '').strip() or None
    nuevo_padre_id = request.form.get('padre_id') or None
    if not nuevo_nombre:
        flash("El nombre no puede estar vacío.", "danger")
        return redirect(url_for('categorias'))
    existente = Categoria.query.filter(Categoria.nombre == nuevo_nombre, Categoria.id != id).first()
    if existente:
        flash("Ya existe otra categoría con ese nombre.", "warning")
        return redirect(url_for('categorias'))
    categoria.nombre = nuevo_nombre
    categoria.icon = nuevo_icon
    
    if nuevo_padre_id:
        pid = int(nuevo_padre_id)
        if pid == categoria.id:
            categoria.padre = None
        else:
            padre = Categoria.query.get(pid)
            
            if padre:
                categoria.padre = padre
    else:
        categoria.padre = None

    db.session.commit()
    registrar_log(f"Editó categoría ID {id} → {nuevo_nombre}")
    flash("Categoría editada correctamente.", "success")
    return redirect(url_for('categorias'))


@app.route('/categorias/<int:id>/eliminar')
@login_required
def eliminar_categoria(id):
    if not current_user.is_admin():
        flash("No autorizado.", "danger")
        return redirect(url_for('categorias'))

    categoria = Categoria.query.get_or_404(id)

    
    if categoria.productos.count() > 0:
        flash(
            f"No se puede eliminar '{categoria.nombre}' porque tiene productos asociados.",
            "warning"
        )
        return redirect(url_for('categorias'))

    
    if Categoria.query.filter_by(padre_id=categoria.id).count() > 0:
        flash(
            f"No se puede eliminar '{categoria.nombre}' porque tiene subcategorías.",
            "warning"
        )
        return redirect(url_for('categorias'))

    db.session.delete(categoria)
    db.session.commit()

    registrar_log(f"Eliminó categoría: {categoria.nombre}")

    flash("Categoría eliminada correctamente.", "success")
    return redirect(url_for('categorias'))


@app.route('/productos')
@login_required
def productos():
    productos = Producto.query.order_by(Producto.nombre.asc()).all()
    return render_template('productos.html', productos=productos)



@app.route('/agregar_producto', methods=['GET', 'POST'])
@login_required
def agregar_producto():
    if not current_user.is_staff():
        return "No autorizado", 403
    if request.method == 'GET':
        categorias = Categoria.query.filter_by(tipo="informatica").order_by(Categoria.nombre).all()
        return render_template('agregar.html', categorias=categorias)

    nombre = request.form['nombre']
    cantidad = int(request.form['cantidad'])
    minimo = int(request.form['minimo'])
    categoria_id = int(request.form['categoria'])

    nuevo = Producto(nombre=nombre, stock=cantidad, minimo=minimo, categoria_id=categoria_id)
    db.session.add(nuevo)
    db.session.commit()

    mov = Movimiento(producto_id=nuevo.id, tipo="entrada", cantidad=cantidad, usuario=current_user.username)
    db.session.add(mov)
    db.session.commit()

    registrar_log(f"{current_user.username} agregó producto: {nombre}")
    return redirect(url_for('index'))


@app.route('/editar_producto/<int:id>', methods=['POST'])
@login_required
def editar_producto(id):
    prod = Producto.query.get_or_404(id)
    if not current_user.is_staff():
        return "No autorizado", 403

    nombre = request.form['nombre']
    stock_nuevo = int(request.form['cantidad'])
    minimo = int(request.form['minimo'])
    categoria_id = int(request.form['categoria'])

    stock_anterior = prod.stock

    prod.nombre = nombre
    prod.stock = stock_nuevo
    prod.minimo = minimo
    prod.categoria_id = categoria_id

    if stock_nuevo != stock_anterior:
        tipo = "entrada" if stock_nuevo > stock_anterior else "salida"
        diferencia = abs(stock_nuevo - stock_anterior)
        mov = Movimiento(producto_id=prod.id, tipo=tipo, cantidad=diferencia, usuario=current_user.username)
        db.session.add(mov)

    db.session.commit()
    registrar_log(f"{current_user.username} editó producto {prod.nombre} (stock {stock_anterior} → {stock_nuevo})")
    flash("Producto editado.", "success")
    return redirect(url_for('index'))


@app.route('/eliminar_producto/<int:id>')
@login_required
@roles_required('admin')
def eliminar_producto(id):
    p = Producto.query.get_or_404(id)
    if p.stock and p.stock > 0:
        mov = Movimiento(producto_id=p.id, tipo="salida", cantidad=p.stock, usuario=current_user.username)
        db.session.add(mov)
    registrar_log(f"Eliminó producto: {p.nombre}")
    db.session.delete(p)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/movimiento/<int:id>', methods=['POST'])
@login_required
@roles_required('admin', 'staff')
def movimiento(id):
    prod = Producto.query.get_or_404(id)
    tipo = request.form['tipo']
    cant = int(request.form['cantidad'])
    if tipo == "salida" and prod.stock < cant:
        flash("No hay stock suficiente.", "danger")
        return redirect(url_for('index'))
    if tipo == "entrada":
        prod.stock += cant
    else:
        prod.stock -= cant
    mov = Movimiento(producto_id=prod.id, tipo=tipo, cantidad=cant, usuario=current_user.username)
    db.session.add(mov)
    db.session.commit()
    registrar_log(f"Movimiento: {tipo} {cant} de {prod.nombre}")
    return redirect(url_for('index'))




@app.route('/historial')
@login_required
def historial():
    q = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)

    query = Movimiento.query.join(Producto)

    if q:
        
        query = query.filter(
            (Producto.nombre.ilike(f"%{q}%")) |
            (Movimiento.usuario.ilike(f"%{q}%"))
        )

    pagination = query.order_by(Movimiento.fecha.desc()).paginate(page=page, per_page=10, error_out=False)
    movs = pagination.items

    return render_template('historial.html', movimientos=movs, pagination=pagination, q=q)



@app.route('/logs')
@login_required
@roles_required('admin')
def logs():
    registros = Log.query.order_by(Log.fecha.desc()).all()
    return render_template('logs.html', logs=registros)



if __name__ == "__main__":
    app.run(debug=True, port=5001)
