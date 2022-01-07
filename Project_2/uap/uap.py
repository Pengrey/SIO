from challenge import createDB, setSecret, updateSecret, getSecret, accountExists, getSeed, getPlays
import os.path
import secrets
import hashlib
import json
import socket

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def pubKeyLoad(website):
    # Load a public key associated with one website
    try:
        with open('keyring/'+website+".key", "rb") as f:
            key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print("[!] Error - Public Key not found.")
        exit(1)
    return key


def privKeyLoad(user):
    # Load this vault's private key
    try:
        with open("keyring/"+user+".pkey", "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        print(f"[!] Error - Private Key for user {user} not found.")
        exit(1)
    return key


def privkey_decrypt(private_key, ciphertext):
    # Use a private key to decrypt a message
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext


def verify_signature(public_key, signature, message):
    # Use a public key to verify a message's signature

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def saveCreds(password):
    # Generate hash
    key = hashlib.sha512(str(password).encode("utf-8")).hexdigest()

    # Generate salt
    salt = secrets.token_hex(8)

    # creds Data
    x = '{ "pswd":\"' + key + '\", "salt": \"' + salt + '\"}'

    # Save hash
    with open('creds.key', 'w') as filekey:
        filekey.write(x)


def checkCreds(password):
    # Generate hash
    key = hashlib.sha512(str(password).encode("utf-8")).hexdigest()

    # Read json from file
    with open('creds.key', 'r') as f:
        file = f.read()

    # Return check
    return key == json.loads(file)['pswd']


def getSalt():
    # Read json from file
    with open('creds.key', 'r') as f:
        file = f.read()

    # Return salt
    return json.loads(file)['salt'].encode('utf-8')


def login():
    prompt = """
                     .--------.
                    / .------. \\
                   / /        \ \\
                   | |        | |
                  _| |________| |_
                .' |_|        |_| '.
                '._____ ____ _____.'
                |     .'____'.     |
                '.__.'.'    '.'.__.'
                '.__  | UAPD |  __.'
                |   '.'.____.'.'   |
                '.____'.____.'____.'
                '.________________.'\n
            """
    print(prompt)

    # Check if there is a safe file
    if os.path.exists("creds.key"):
        print("[!] Please login:")
        password = input("[?] Password: ")

        # Check password
        if checkCreds(password):
            print("[!] Welcome back.")
        else:
            print("[!] Wrong password!")
            exit()
    else:
        print("[!] Please register new user:")
        password = input("[?] Password: ")
        saveCreds(password)

    return password


def registerAccount(password):
    # Get info from user
    website = input("[?] Website: ")
    user = input("[?] Username: ")
    accountPassword = input("[?] Password: ")

    # Save account onto database
    if not accountExists(website, user):
        # get salt bytes
        salt = getSalt()

        # generate secret from password
        secret = bytes(getSeed(accountPassword), 'utf-8')

        # create password bytes
        password = bytes(password, 'utf-8')

        # set secret on db
        setSecret(website, user, secret, password, salt)
    else:
        print("[!] Account already exists!")


def serverStart(password):

    # Send message encrypted with a symmetric key
    def send_msg(msg, key):
        msg = json.dumps(msg)
        # Encode the message so it can be sent via socket
        better_msg = str(msg).encode("utf-8")
        f = Fernet(key)
        better_msg = f.encrypt(better_msg)
        # Gets the size of the *encoded* message into a 2-byte format
        size = len(better_msg).to_bytes(2, 'big')
        conn.sendall(size)
        conn.sendall(better_msg)
        return

    # Receive message encrypted with a symmetric key
    def recv_msg(key):
        # Receive the first two bytes, which contain the size of the msg
        size = int.from_bytes(conn.recv(2), byteorder="big")
        # Receive the rest of the message
        msg = conn.recv(size)
        if msg == b'':
            return ''
        f = Fernet(key)
        msg = f.decrypt(msg)
        msg = msg.decode('utf-8')
        try:
            msg = json.loads(msg)
            #print(f"Received: {msg}")
        except:
            print("[!] Malformed message!")
            return ""
        return msg

    # Receive a plaintext message - To be used with the first, 'info' message
    def info_recv_msg():
        size = int.from_bytes(conn.recv(2), byteorder="big")
        msg = conn.recv(size)
        msg = msg.decode('utf-8')
        try:
            msg = json.loads(msg)
        except:
            print("[!] Malformed message! ")
            return ""
        try:
            msg.get("info")
        except:
            print("[!] First Message was not an Info-type message")
            return ""
        return msg

    # Receive a message, encrypted with the UAP's public key
    # And the signature of that message, created with the webapp's private key
    def handshake_recv_msg(pubkey, privkey):
        size = int.from_bytes(conn.recv(2), byteorder="big")
        msg = conn.recv(size)

        size = int.from_bytes(conn.recv(2), byteorder="big")
        signature = conn.recv(size)

        msg = privkey_decrypt(privkey, msg)

        if not verify_signature(pubkey, signature, msg):
            print("[!] SIGNATURE IS NOT VALID")
            return ""

        msg = msg.decode('utf-8')
        try:
            msg = json.loads(msg)
        except:
            print("[!] Malformed message! ")
            return ""
        return msg

    salt = getSalt()
    HOST = ""
    PORT = 9001

    # Adapted from: https://realpython.com/python-sockets/#tcp-sockets
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            print("[-] Accepted Connection")
            with conn:
                print("[-] Waiting for message...")
                # Get the initial message and the information contained in it
                msg = info_recv_msg()
                user = msg.get("user")
                website = msg.get("website")
                uap_privkey = privKeyLoad(user)           # Load the UAP's private key
                # Load the key that matches the website we're authenticating with
                app_pubkey = pubKeyLoad(website)
                msg = handshake_recv_msg(app_pubkey, uap_privkey)
                if msg == "":                         # Something went wrong when receiving the 'handshake' message
                    s.close()
                    return
                #print(f"[-] Received msg:  {msg}")
                if msg.get("command") == "start":
                    key = msg.get("key")
                    secret = getSecret(website, user, password, salt)
                    if secret == None:
                        print(
                            "[!] Did you forget to register an account in the UAP?")
                        s.close()
                        return
                    # Generate the challenge for this login attempt
                    plays = getPlays(secret)
                    while plays != []:
                        gameOver = False              # Only used in case a message is malformed or incorrect
                        if not gameOver:
                            msg = {
                                "command": "play",
                                "move": plays[0][2]
                            }
                            send_msg(msg, key)
                            try:
                                rmsg = recv_msg(key)
                            except:
                                gameOver = True
                            if rmsg.get("command") == "next":
                                plays = plays[1:]
                                continue
                            else:
                                gameOver = True
                                print("[!!] ERROR -> Unexpected Message")
                    # Receive the last message -> 'end'
                    msg = recv_msg(key)

                    # After receiving confirmation from the website that the login was successful
                    # Update the seed used to calculate the plays, to prevent possible replay attacks

                    # This operation must be mirrored on the authenticating client

                    if msg != '' or msg != b'' or msg.get['command'] == 'end':
                        #print("[-] Calculating new digest...")
                        secret = getSeed(
                            getSecret(website, user, password, salt)).encode('utf-8')
                        updateSecret(website, user, secret, password, salt)

                        # If the client doesn't receive this message, it will revert the secret update
                        msg = {
                            "command": "ack_end"
                        }
                        send_msg(msg, key)

                print("[-] Completed")
                print("[-] Waiting for next connection...")


def listenToRequests(password):
    print("[!] Server starting...")
    try:
        print("[!] Server up (press ctrl+c to quit)")
        serverStart(password)
    except KeyboardInterrupt:
        print("\n[!] Shutting daemon down...")


def main():
    password = login()

    # Create DB if its not created already
    if createDB():
        print("[!] Created new safe!")

    while True:
        try:
            print("[?] Choose one of the options:\n       1 - Register new account\n       2 - Start daemon\n       3 - quit")
            inpt = input("> ")
            if(inpt == "1"):
                # The account is created on the database, but its rsa keypair must be added
                # manually both on UAC (private key) and on the webapp (public key)
                registerAccount(password)
            elif(inpt == "2"):
                try:
                    listenToRequests(password.encode('utf-8'))
                except OSError:
                    print("[!] Address already in use, wait a bit.")
            elif(inpt == "3"):
                print("\n[!] Shutting Down...")
                break
            else:
                print("[!] Invalid command!")
        except KeyboardInterrupt:
            print("\n[!] Shutting Down...")
            break


if __name__ == "__main__":
    main()
