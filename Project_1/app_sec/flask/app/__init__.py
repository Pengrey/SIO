from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors


app = Flask(__name__, static_folder='static', static_url_path='')
# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'somerandomkey'

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'db'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'users'

# Intialize MySQL
mysql = MySQL(app)


from app import views

