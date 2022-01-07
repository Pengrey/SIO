from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.types import PUBLIC_KEY_TYPES
from flask import Flask, render_template, request
from challenge import getSecret, accountExists, getSeed, getPlays, setSecret, createDB, updateSecret
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import json
import socket

app = Flask(__name__)


# Load a RSA Public Key (Keys corresponding to each user)
def pubKeyLoad(username):
    try:
        with open('Keychain/'+username+".key", "rb") as f:
            key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print("[!] Error - Public Key not found.")
        exit(1)
    return key

# Load a RSA Private Key (This webapp's key)


def privKeyLoad():
    try:
        with open("Keychain/app.pkey", "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        print("[!] Error - Private Key not found.")
        exit(1)
    return key


# Encrypt a message using a user's public key, so only they can decrypt
def pubkey_encrypt(public_key: PUBLIC_KEY_TYPES, message: bytes):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext

# Sign a message with the app's private key, so the receiver can be sure of the source


def privkey_sign(private_key, message):
    #print(f"Attempting to sign \n{message}")
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


# Authenticate the user
def game_start(username):

    # Send a cleartext message - only used for the first 'info' message
    def send_info_msg(s):
        #print("Sending Info message")
        msg = {
            "command": "info",
            "user": username,
            "website": "bazinga"
        }
        msg = json.dumps(msg)
        # Encode the message so it can be sent via socket
        better_msg = str(msg).encode("utf-8")
        # Gets the size of the *encoded* message into a 2-byte format
        size = len(better_msg).to_bytes(2, 'big')
        s.sendall(size)
        s.sendall(better_msg)
        return

    # Send the handshake message - Encrypted and signed via RSA
    # This contains the key used for the rest of communications
    def handshake_send_msg(s, pubkey, privkey):
        #print("Sending handshake message")
        msg = {
            "command": "start",
            "key": key.decode('utf-8')
        }
        msg = json.dumps(msg)

        better_msg = str(msg).encode("utf-8")
        signature = privkey_sign(privkey, better_msg)

        better_msg = pubkey_encrypt(pubkey, better_msg)

        size = len(better_msg).to_bytes(2, 'big')
        s.sendall(size)
        s.sendall(better_msg)

        size = len(signature).to_bytes(2, 'big')
        s.sendall(size)
        s.sendall(signature)
        return

    # Send a message encrypted with a symmetric key
    def send_msg(msg, s, key):
        msg = json.dumps(msg)

        better_msg = str(msg).encode("utf-8")
        f = Fernet(key)
        better_msg = f.encrypt(better_msg)
        size = len(better_msg).to_bytes(2, 'big')
        s.sendall(size)
        s.sendall(better_msg)
        return

    # Receive a message encrypted with a symmetric key
    def recv_msg(s, key):
        # Receive the first two bytes, which contain the size of the msg
        size = int.from_bytes(s.recv(2), byteorder="big")
        # Receive the rest of the message
        msg = s.recv(size)
        f = Fernet(key)
        msg = f.decrypt(msg)
        #print(f"TEST {msg}")
        msg = msg.decode('utf-8')
        try:
            msg = json.loads(msg)
        except:
            print("[!] Malformed message!")
            return ""
        return msg

    HOST = "localhost"
    PORT = 9001
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    send_info_msg(s)
    key = Fernet.generate_key()

    # Load the needed keys
    thisapp_privkey = privKeyLoad()
    users_pubkey = pubKeyLoad(username)

    handshake_send_msg(s, users_pubkey, thisapp_privkey)

    # ===========- CHALLENGES START -=============

    gameOver = False
    secret = getSecret(username)
    #print(f"Secret: {secret}")
    plays = getPlays(secret)  # Default: 154 moves

    #print(f"\nGENERATED PLAYS: {plays} \n")
    valid = True

    while plays:
        if not gameOver:  # Should only trigger in case of comms error
            try:
                msg = recv_msg(s, key)
                # Only 'play' messages should be received at this stage
                if msg.get('command') != 'play':
                    print("[!] Malformed message, stopping.")
                    gameOver = True
                else:
                    if msg.get("move") != plays[0][2]:
                        # Wrong move, the user won't be authenticated (But keeps playing)
                        valid = False
                    msg = {
                        "command": "next"
                    }
                    send_msg(msg, s, key)
                    #print(f"Expecting:\n {plays[0][2]}")
                    plays = plays[1:]

            except AttributeError:
                print("[!] Malformed Message!")
                return False
        else:
            break

    if valid:                   # User authenticated successfully, change the secret used
        # Mirrored in the UAP's side
        old_secret = secret       # If we don't get a message ackowledging our change, revert it
        secret = getSeed(getSecret(username))
        updateSecret(username, secret)

        msg = {
            "command": "end"
        }
        send_msg(msg, s, key)
        msg = recv_msg(s, key)

        if msg == "" or msg["command"] != "ack_end":
            print("[!] REVERTING SECRET UPDATE")
            updateSecret(username, old_secret)

    print(f"[-] Authenticated Successfully? {valid}")

    return valid


def doRegister(user, email, password):
    if not accountExists(user):
        secret = getSeed(password)
        setSecret(email, user, secret)
        return True
    return False


@app.route('/')
def index():
    createDB()
    return render_template('Login.html')


@app.route('/welcome', methods=['POST'])
def welcome():
    createDB()

    username = request.form['username']
    result = False
    try:
        if accountExists(username):
            result = game_start(username)
        else:
            result = False
    except ConnectionRefusedError:
        text = "Local UAP Server not found!"
        print(text)
        return render_template("Login.html", text=text)

    if result:  # If the login succeeded
        return render_template('Welcome.html')
    else:
        text = "Invalid Credentials"
        return render_template("Login.html", text=text)


@app.route('/register', methods=['POST'])
def register():
    createDB()

    email = request.form['email']
    username = request.form['username2']
    password = request.form['password']

    result = doRegister(username, email, password)
    if result:
        text = "Register Successful"
        return render_template('Login.html', text=text)
    else:
        text = "ERROR: The user already exists"
        return render_template("Login.html", text=text)
