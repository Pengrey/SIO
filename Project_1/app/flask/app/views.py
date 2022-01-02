from app import app
import os
from flask import render_template, request, send_from_directory, redirect, url_for, session, Flask, make_response
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import _pickle as cPickle
from base64 import b64decode,b64encode

mysql = MySQL(app)

with open("posts.txt",'ab+') as f:
    cPickle.dump([],f)
    pass
# User class used for cookies
class User(object):
    def __init__(self, name):
        self.name = name
    def __str__(self):
        return self.name



posts=cPickle.load(open("posts.txt","rb"))



print(f"\n\n LOADED POSTS: {posts}")

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
    cookie = request.cookies.get('value')
    if cookie:
        user = cPickle.loads(b64decode(cookie))
        if user.name:
            return redirect("/")
    
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        q=f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}' "
        cursor.execute(q)
        myresult = cursor.fetchall()
        
        if myresult:
            account = myresult[0]
        else:
            account=None

        # If account exists in accounts table in out database
        if account:
            # Cookies
            user = User(account['username'])
            userdata = b64encode(cPickle.dumps(user))

            # Admin filter
            if(user.name != "root"):
                res = make_response(redirect("/"))
                res.set_cookie("value", userdata)
            else:
                res = make_response(redirect("/admin"))
                res.set_cookie("value", userdata)

            # Redirect to home page
            return res
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect username/password!'
    # Show the login form with message (if any)
    return render_template('login.html', msg=msg)


@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
    res = make_response(redirect("/login"))
    res.set_cookie('value', '', expires=0)
    # Redirect to login page
    return res



@app.route('/register', methods=['GET', 'POST'])
def register():
    cookie = request.cookies.get('value')
    if cookie:
        user = cPickle.loads(b64decode(cookie))
        if user.name:
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
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif not username or not password:
            msg = 'Please fill out the form!'
        else:
            cursor.execute('INSERT INTO users VALUES (%s, %s)', (username, password))
            mysql.connection.commit()
            msg = 'You have successfully registered!'
            
            # Cookies
            user = User(username)
            userdata = b64encode(cPickle.dumps(user))
            res = make_response(redirect("/"))
            res.set_cookie("value", userdata)
            
            # Redirect to home page
            return res
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)


@app.route('/home', methods=['GET', 'POST'])
def submit():
    cookie = request.cookies.get('value')
    user=None
    message=None
    if cookie:
        user = cPickle.loads(b64decode(cookie))
    if request.method == 'POST':
        if request.form.get("submit") :
                # Create variables for easy access
                desc = request.form['fdescription']
                sight_type = request.form['type']
                poster_name = request.form['fname']
                location=request.form['flocation']
                country = request.form['fcountry']
                date = request.form['fdate']
                witnesses = request.form['fwitnesses']


                content = f"""
                AN {sight_type} WAS SEEN AT {country},{location} IN {date} BY {poster_name}!!
                {witnesses} WITNESSES CONFIRMED!

                DETAILS:
                    {desc}
                """
                #cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                #
                #cursor.execute('INSERT INTO posts (username,content) VALUES (%s, %s)', (user, content))
                #mysql.connection.commit()
                posts.append({"username":user,"content":content})
                print(f"POSTS\n\n\n {posts}")
                with open("posts.txt", "wb") as fp:   #Pickling
                    cPickle.dump(posts, fp)

    #cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    #cursor.execute('SELECT * FROM posts')
    #message = cursor.fetchall()
    #mysql.connection.commit()

    message=[m['content'] for m in posts]
    print(f">>\n\n>> {posts}")

    if not user:
            return render_template('home.html', message=message,user=user)
    return render_template('home.html', message=message,user=user)

@app.route("/admin")
def admin_panel():
    cookie = request.cookies.get('value')
    if cookie:
        user = cPickle.loads(b64decode(cookie))
        return render_template('admin.html')
    else:
        return redirect("/login")


    
@app.get('/shutdown')
def shutdown():
    return 'Emergency Shutdown Activated -- Shredding In Progress'
    