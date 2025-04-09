import os

class Config:
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://root:senha@localhost:3306/meu_banco_de_dados'
    SQLALCHEMY_TRACK_MODIFICATIONS = False