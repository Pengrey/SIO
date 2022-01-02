from app import app
import os
from flask import render_template, request, send_from_directory, redirect, url_for, session, Flask, make_response
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import _pickle as cPickle
from base64 import b64decode,b64encode
import hashlib
from random import seed,randint
seed(None)
mysql = MySQL(app)

@app.route("/")
def index():
    return redirect("/home")

# robots.txt file
@app.route('/robots.txt')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])

# Route for handling the login page logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    msg = ''
    if 'loggedin' in session.keys():
        if session['loggedin'] == True:
            return redirect("/")

    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""SELECT * FROM users WHERE username like %(username)s AND password like %(password)s LIMIT 1; """,{'username':username,'password':hashlib.sha256(str.encode(password,'utf-8')).hexdigest() } )
        myresult = cursor.fetchall()
        
        if myresult:
            account = myresult[0]
        else:
            account=None

        # If account exists in accounts table in our database
        if account:
            # Cookies
            session['username'] = account['username']
            is_admin = myresult[0]['is_admin']
            
            # Admin filter
            if is_admin == 0:
                session['loggedin'] = True
                session['is_admin'] = False
                return redirect("/")
            else:
                session['loggedin'] = True
                session['is_admin'] = True
                return redirect("/admin")
            
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect username/password!'
    # Show the login form with message (if any)
    return render_template('login.html', msg=msg)


@app.route('/logout')
def logout():
   session.pop('loggedin', None)
   session.pop('username', None)
   session.pop('is_admin', None)
   # Redirect to login page
   return redirect("/login")



@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'loggedin' in session.keys():
        if session['loggedin'] == True:
            return redirect("/")
        

    # Output message if something goes wrong...
    msg = ''
    # Check if "username", "password"  POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
         # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s LIMIT 1', (username,))
        account = cursor.fetchone()

        # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif not username or not password:
            msg = 'Please fill out the form!'
        else:
            passwordhash = hashlib.sha256(str.encode(password,'utf-8')).hexdigest()
            cursor.execute('INSERT INTO users VALUES (%s, %s,0)', (username, passwordhash))

            mysql.connection.commit()
            msg = 'You have successfully registered!'
            
            # Cookies
            session['loggedin'] = True
            session['username'] = username
            session['is_admin'] = False

            # Redirect to home page
            return redirect("/")
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)


@app.route('/home', methods=['GET', 'POST'])
def submit():
    user=None
    message=None
    if 'loggedin' in session.keys():
        user = session['username']

    if request.method == 'POST':
        if request.form.get("submit"):
            message=request.form['fdescription']

    if not user:
            return render_template('home.html', message=message,user=user)

    return render_template('home.html', message=message,user=user)

@app.route("/admin")
def admin_panel():
    if 'loggedin' in session.keys():
        if session['loggedin'] == True:
            if session['is_admin']:
                return render_template('admin.html')
            else:
                return redirect("/home")
    else:
        return redirect("/home")
    
    
@app.get('/shutdown')
def shutdown():
    return 'Emergency Shutdown Activated -- Shredding In Progress'