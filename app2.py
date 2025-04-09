from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
import pandas as pd

app = Flask(__name__)

# Configurando a URI do banco de dados MariaDB
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://admin:adminpassword@localhost/HomeFusionOS'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Desativa o rastreamento de modificações

# Inicializando a instância do SQLAlchemy
db = SQLAlchemy(app)

# Definindo um modelo (tabela) no MariaDB com SQLAlchemy
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(255), nullable=True)

class Access(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(80), nullable=True)
    time = db.Column(db.DateTime, nullable=True)

class App(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    name = db.Column(db.String(80), nullable=True)
    path = db.Column(db.String(255), nullable=True)

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

# Função para criar as tabelas automaticamente no banco de dados
def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    # Chama a função para criar as tabelas automaticamente ao iniciar a aplicação
    create_tables()
    app.run(debug=True)
