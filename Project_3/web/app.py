from flask import Flask, render_template, render_template_string, g, redirect, session, url_for, request, make_response, jsonify
from werkzeug.utils import secure_filename
import os
import logging
import base64
import datetime
import time
import json
from auth import *
import pickle
import urllib
import sys

UPLOAD_FOLDER = './static/gallery'

ADMIN_USER='admin'
ADMIN_PASS='75debe8ecad2b043072ce03d1dc3e635'

logging.basicConfig(level=logging.DEBUG,
                    format="[%(levelname)s] - %(asctime)s: %(message)s")

logger = logging.getLogger("app")

app = Flask(__name__, template_folder='templates')

app.secret_key = os.urandom(16)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# data source
def get_pics():
    
    data = []

    if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], 'data')):
        with open(os.path.join(app.config['UPLOAD_FOLDER'], 'data'), 'rb') as f:
            data = pickle.loads(f.read())
    return data

@app.errorhandler(404)
def page_not_found(e):
    template = '''
 <div class="center-content error">
 <h1>Oops! That page doesn't exist.</h1>
 <pre>%s</pre>
 </div>
 ''' % (urllib.parse.unquote(request.url))
    return render_template_string(template, dir=dir, help=help, locals=locals), 404

@app.route("/upload", methods=['GET', 'POST'])
def upload():
    user = authenticate_user(app.secret_key, request)

    if user != 'admin':
        return redirect(url_for('index'))

    if request.method == 'GET':
        resp = make_response(render_template('upload.html', user=user))
        return resp

    if request.method == 'POST':
        if 'name' not in request.form:
            response = jsonify({'message':'Name is missing'})
            return response

        # check if the post request has the file part
        if 'file' not in request.files:
            response = jsonify({'message':'File is missing'})
            return response

        file = request.files['file']
        
        if file.filename == '':
            response = jsonify({'message':'File is missing'})
            return response
        
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            if os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], 'data')):

                with open(os.path.join(app.config["UPLOAD_FOLDER"], 'data'), 'rb') as f:
                    try:
                        data = pickle.loads(f.read())
                    except:
                        data = []
            else:
                data = []

            with open(os.path.join(app.config['UPLOAD_FOLDER'], 'data'), 'wb') as f:
                data.append({'name': request.form['name'], 'url': f'/static/gallery/{filename}'})
                f.write(pickle.dumps(data))
            
            return redirect(url_for('index'))
 

@app.route("/", methods=['GET'])
def index():
    user = authenticate_user(app.secret_key, request)
    
    print(f"GET / User={user}", file=sys.stderr)
    
    # Handle reverse proxies
    if 'X-Forwarded-For' in request.headers:
        ip=request.headers['X-Forwarded-For']
    else:
        ip=request.remote_addr

    resp = make_response(render_template('index.html', user=user, pics=get_pics(), ip=ip))
    
    if user == 'guest':
        resp.set_cookie('auth', get_cookie(app.secret_key, user))
    
    return resp

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in request.form and 'pass' in request.form:
        if request.form['user'] == ADMIN_USER and request.form['pass'] == ADMIN_PASS:
            resp = make_response(render_template('index.html'))
            resp.set_cookie('auth', get_cookie(app.secret_key, ADMIN_USER))
            print("Authentication success")
            return resp
        else:
            print(f"Authentication failed for: {request.form['user']}/{request.form['pass']}")

    response = jsonify({'message':' Authentication failed'})
    return response, 401

@app.after_request
def add_header(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=False)
