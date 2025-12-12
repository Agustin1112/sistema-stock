from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()




class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer")


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
    nombre = db.Column(db.String(120), nullable=False)

    
    tipo = db.Column(db.String(50), nullable=False, default="informatica")

    def __repr__(self):
        return f"<Categoria {self.nombre} tipo={self.tipo}>"



class Producto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(150), nullable=False)

    
    stock = db.Column(db.Integer, default=0, nullable=False)

    
    minimo = db.Column(db.Integer, default=0, nullable=False)

    
    categoria_id = db.Column(db.Integer, db.ForeignKey('categoria.id'), nullable=False)
    categoria = db.relationship('Categoria', backref='productos')

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

   
    @property
    def cantidad(self):
        return self.stock

    @cantidad.setter
    def cantidad(self, value):
        self.stock = int(value)

    def __repr__(self):
        return f"<Producto {self.nombre} stock={self.stock}>"



class Movimiento(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    producto_id = db.Column(db.Integer, db.ForeignKey("producto.id"), nullable=False)
    producto = db.relationship("Producto")

    tipo = db.Column(db.String(20), nullable=False)
    cantidad = db.Column(db.Integer, nullable=False)

    usuario = db.Column(db.String(120))
    fecha = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Mov {self.tipo} {self.cantidad} de {self.producto.nombre}>"

