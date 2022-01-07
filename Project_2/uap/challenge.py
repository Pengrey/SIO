import base64
import hashlib
import sqlite3
import os.path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def createDB():
    if not os.path.exists("uap.db"):
        # connecting to the database
        connection = sqlite3.connect("uap.db")

        # cursor
        crsr = connection.cursor()
        
        # SQL command to create a table in the database
        sql_command = """
                        CREATE TABLE IF NOT EXISTS SAFE ( 
                            WEBSITE TEXT,
                            USER TEXT,
                            SECRET TEXT,
                            PRIMARY KEY (website, user)
                        );
                    """
        
        # execute the statement
        crsr.execute(sql_command)

        # close the connection
        connection.close()

        # Return true if database was created
        return True
    else:
        return False

def setSecret(website, user, secret, password, salt):
    # encrypt secret
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )

    # encrypt secret
    key = base64.urlsafe_b64encode(kdf.derive(password))

    f = Fernet(key)

    secret = f.encrypt(secret).decode('utf-8')

    # connecting to the database
    connection = sqlite3.connect("uap.db")
    
    # cursor
    crsr = connection.cursor()
    
    # SQL command to insert data into created table
    sql_command = f"""
                    INSERT INTO SAFE (WEBSITE,USER,SECRET) \
                    VALUES (\'{website}\',\'{user}\',\'{secret}\');
                """
    
    # execute the statement
    crsr.execute(sql_command)

    # Save the changes
    connection.commit()

    # close the connection
    connection.close()

def updateSecret(website, user, secret, password, salt):
    # encrypt secret
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )

    # encrypt secret
    key = base64.urlsafe_b64encode(kdf.derive(password))

    f = Fernet(key)

    secret = f.encrypt(secret).decode('utf-8')

    # connecting to the database
    connection = sqlite3.connect("uap.db")
    
    # cursor
    crsr = connection.cursor()
    
    # SQL command to insert data into created table
    sql_command = f"""
                    UPDATE SAFE 
                    SET SECRET = \'{secret}\'
                    WHERE WEBSITE = \'{website}\' 
                    AND USER = \'{user}\';
                """
    
    # execute the statement
    crsr.execute(sql_command)

    # Save the changes
    connection.commit()

    # close the connection
    connection.close()

def accountExists(website, user):
    # connecting to the database
    connection = sqlite3.connect("uap.db")

    # cursor
    crsr = connection.cursor()
    
    # get user Secret
    sql_command = f"""
                    SELECT user FROM SAFE 
                    WHERE WEBSITE = \'{website}\' 
                    AND USER = \'{user}\';
                    """
    
    # execute the statement
    result = crsr.execute(sql_command).fetchall()

    # close the connection
    connection.close()

    return False if result == [] else True

def getSecret(website, user,  password, salt):
    # connecting to the database
    connection = sqlite3.connect("uap.db")
    
    # cursor
    crsr = connection.cursor()
    
    # get user Secret
    sql_command = f"""
                    SELECT secret FROM SAFE 
                    WHERE WEBSITE = \'{website}\' 
                    AND USER = \'{user}\';
                    """
    
    # execute the statement
    result = crsr.execute(sql_command).fetchone()

    # close the connection
    connection.close()

    if result != None:
        # decrypt secret
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )

        # encrypt secret
        key = base64.urlsafe_b64encode(kdf.derive(password))

        f = Fernet(key)

        secret = f.decrypt(bytes(result[0], 'utf-8')).decode('utf-8')

        return secret
    
    return result

def getSeed(secret):
    return hashlib.sha512(secret.encode("utf-8")).hexdigest()

def getPlays(seed:str, limit=154):
    plays = ["Rock", "Lizard", "Spock", "Scissors", "Paper"]

    statesHash = int(seed, 16)
    return [(plays[int(x) % len(plays)], plays[(int(x) + 2) % len(plays)], plays[(int(x) + 4) % len(plays)]) for x in str(statesHash)[:limit]]