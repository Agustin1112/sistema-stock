from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import text
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stock.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# -----------------------------
# MODELOS
# -----------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer")


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # ---------- Roles ----------
    def is_admin(self):
        return self.role == "admin"

    def is_staff(self):
        return self.role in ("admin", "staff")

    def is_viewer(self):
        return self.role == "viewer"


class Categoria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(150), unique=True, nullable=False)
    tipo = db.Column(db.String(50), default="general", nullable=False)


class Producto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(150), nullable=False)

    categoria_id = db.Column(db.Integer, db.ForeignKey('categoria.id'), nullable=False)
    categoria = db.relationship('Categoria', backref='productos')

    stock = db.Column(db.Integer, default=0, nullable=False)
    minimo = db.Column(db.Integer, default=0, nullable=False)

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
    producto_id = db.Column(db.Integer, db.ForeignKey('producto.id'))
    tipo = db.Column(db.String(20))
    cantidad = db.Column(db.Integer)
    fecha = db.Column(db.DateTime, default=datetime.now)
    producto = db.relationship('Producto')


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(150))
    accion = db.Column(db.String(500))
    fecha = db.Column(db.DateTime, default=datetime.now)


def registrar_log(texto):
    if current_user.is_authenticated:
        usuario = current_user.username
    else:
        usuario = "desconocido"

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
            column_names = [r[1] for r in res]
            if 'tipo' not in column_names:
                conn.execute(text("ALTER TABLE categoria ADD COLUMN tipo VARCHAR DEFAULT 'general'"))
            conn.close()
        except:
            pass

        
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", role="admin")
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()

       
        if Categoria.query.count() == 0:
            categorias_info = [
                "Monitores", "Teclados", "Notebooks",
                "Computadoras", "Accesorios", "Impresoras"
            ]

            for c in categorias_info:
                db.session.add(Categoria(nombre=c, tipo="informatica"))

            db.session.commit()


crear_datos_iniciales()



@app.context_processor
def inyectar_fecha():
    return {"current_year": datetime.now().year}



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
    categorias = Categoria.query.filter_by(tipo="informatica").order_by(Categoria.nombre).all()

    return render_template(
        'index.html',
        productos=productos,
        categorias=categorias,
        q_name=q_name,
        q_cat=q_cat,
        q_min=q_min,
        q_max=q_max,
        q_state=q_state
    )



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()

        if user and user.check_password(request.form['password']):
            login_user(user)
            registrar_log("Inicio de sesión")
            return redirect(url_for('index'))

        flash("Usuario o contraseña incorrectos.", "danger")

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    registrar_log("Cierre de sesión")
    logout_user()
    return redirect(url_for('login'))



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
def usuarios():
    if not current_user.is_admin():
        return "No autorizado", 403

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

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
def editar_usuario(id):
    if not current_user.is_admin():
        return "No autorizado", 403

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
def eliminar_usuario(user_id):
    if not current_user.is_admin():
        return "No autorizado", 403

    usuario = User.query.get_or_404(user_id)

    if usuario.username == "admin":
        flash("No podés eliminar al admin principal", "danger")
        return redirect(url_for('usuarios'))

    db.session.delete(usuario)
    db.session.commit()

    flash("Usuario eliminado correctamente", "success")
    return redirect(url_for('usuarios'))



@app.route('/categorias')
@login_required
def categorias():
    categorias = Categoria.query.filter_by(tipo="informatica").order_by(Categoria.nombre).all()
    return render_template('categorias.html', categorias=categorias)


@app.route('/agregar_categoria', methods=['POST'])
@login_required
def agregar_categoria():
    if not current_user.is_admin():
        return "No autorizado", 403

    nombre = request.form['nombre'].strip()

    if not nombre:
        flash("El nombre no puede estar vacío.")
        return redirect(url_for('categorias'))

    if Categoria.query.filter_by(nombre=nombre).first():
        flash("Ya existe esa categoría.")
        return redirect(url_for('categorias'))

    nueva = Categoria(nombre=nombre, tipo="informatica")
    db.session.add(nueva)
    db.session.commit()

    registrar_log(f"Agregó categoría: {nombre}")
    flash("Categoría agregada correctamente.")
    return redirect(url_for('categorias'))


@app.route('/editar_categoria/<int:id>', methods=['POST'])
@login_required
def editar_categoria(id):
    if not current_user.is_admin():
        return "No autorizado", 403

    nuevo_nombre = request.form['nuevo_nombre'].strip()

    if not nuevo_nombre:
        flash("El nombre no puede estar vacío.")
        return redirect(url_for('categorias'))

    categoria = Categoria.query.get(id)

    if not categoria:
        flash("La categoría no existe.")
        return redirect(url_for('categorias'))

    if Categoria.query.filter_by(nombre=nuevo_nombre).first():
        flash("Ya existe esa categoría.")
        return redirect(url_for('categorias'))

    categoria.nombre = nuevo_nombre
    categoria.tipo = "informatica"
    db.session.commit()

    registrar_log(f"Editó categoría ID {id}")
    flash("Categoría editada.")
    return redirect(url_for('categorias'))


@app.route('/eliminar_categoria/<int:id>')
@login_required
def eliminar_categoria(id):
    if not current_user.is_admin():
        return "No autorizado", 403

    categoria = Categoria.query.get(id)

    if not categoria:
        flash("La categoría no existe.")
        return redirect(url_for('categorias'))

    if categoria.productos:
        flash("No se puede eliminar: tiene productos.")
        return redirect(url_for('categorias'))

    db.session.delete(categoria)
    db.session.commit()

    registrar_log(f"Eliminó categoría: {categoria.nombre}")
    flash("Categoría eliminada.")
    return redirect(url_for('categorias'))



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

    prod = Producto(
        nombre=nombre,
        stock=cantidad,
        minimo=minimo,
        categoria_id=categoria_id
    )

    db.session.add(prod)
    db.session.commit()

    registrar_log(f"Agregó producto: {nombre}")
    return redirect(url_for('index'))


@app.route('/editar_producto/<int:id>', methods=['POST'])
@login_required
def editar_producto(id):
    if not current_user.is_staff():
        return "No autorizado", 403

    prod = Producto.query.get(id)
    if not prod:
        flash("Producto no encontrado.")
        return redirect(url_for('index'))

    prod.nombre = request.form['nombre']
    prod.stock = int(request.form['cantidad'])
    prod.minimo = int(request.form['minimo'])
    prod.categoria_id = int(request.form['categoria'])

    db.session.commit()

    registrar_log(f"Editó producto: {prod.nombre}")

    flash("Producto editado.")
    return redirect(url_for('index'))


@app.route('/eliminar_producto/<int:id>')
@login_required
def eliminar_producto(id):
    if not current_user.is_admin():
        return "No autorizado", 403

    p = Producto.query.get(id)
    registrar_log(f"Eliminó producto: {p.nombre}")

    db.session.delete(p)
    db.session.commit()
    return redirect(url_for('index'))



@app.route('/movimiento/<int:id>', methods=['POST'])
@login_required
def movimiento(id):
    if not current_user.is_staff():
        return "No autorizado", 403

    prod = Producto.query.get(id)
    tipo = request.form['tipo']
    cant = int(request.form['cantidad'])

    if tipo == "salida" and prod.stock < cant:
        flash("No hay stock suficiente.")
        return redirect(url_for('index'))

    if tipo == "entrada":
        prod.stock += cant
    else:
        prod.stock -= cant

    mov = Movimiento(producto_id=id, tipo=tipo, cantidad=cant)
    db.session.add(mov)
    db.session.commit()

    registrar_log(f"Movimiento: {tipo} {cant} de {prod.nombre}")
    return redirect(url_for('index'))



@app.route('/historial')
@login_required
def historial():
    movs = Movimiento.query.order_by(Movimiento.fecha.desc()).all()
    return render_template('historial.html', movimientos=movs)



@app.route('/logs')
@login_required
def logs():
    if not current_user.is_admin():
        return "No autorizado", 403

    registros = Log.query.order_by(Log.fecha.desc()).all()
    return render_template('logs.html', logs=registros)



if __name__ == "__main__":
    app.run(debug=True, port=5001)
