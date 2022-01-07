import base64
import hashlib
import sqlite3
import os.path

def createDB():
    if not os.path.exists("website.db"):
        # connecting to the database
        connection = sqlite3.connect("website.db")

        # cursor
        crsr = connection.cursor()
        
        # SQL command to create a table in the database
        sql_command = """
                        CREATE TABLE IF NOT EXISTS CREDS ( 
                            email TEXT,
                            USER TEXT,
                            SECRET TEXT,
                            PRIMARY KEY (email, user)
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

def setSecret(email, user, secret):
    # connecting to the database
    connection = sqlite3.connect("website.db")
    
    # cursor
    crsr = connection.cursor()
    
    # SQL command to insert data into created table
    sql_command = f"""
                    INSERT INTO CREDS (email,USER,SECRET) \
                    VALUES (\'{email}\',\'{user}\',\'{secret}\');
                """
    
    # execute the statement
    crsr.execute(sql_command)

    # Save the changes
    connection.commit()

    # close the connection
    connection.close()

def updateSecret(user, secret):
    # connecting to the database
    connection = sqlite3.connect("website.db")
    
    # cursor
    crsr = connection.cursor()
    
    # SQL command to insert data into created table
    sql_command = f"""
                    UPDATE CREDS 
                    SET SECRET = \'{secret}\'
                    WHERE USER = \'{user}\';
                """
    
    # execute the statement
    crsr.execute(sql_command)

    # Save the changes
    connection.commit()

    # close the connection
    connection.close()

def accountExists(user):
    # connecting to the database
    connection = sqlite3.connect("website.db")

    # cursor
    crsr = connection.cursor()
    
    # get user Secret
    sql_command = f"""
                    SELECT user FROM CREDS 
                    WHERE USER = \'{user}\';
                    """
    
    # execute the statement
    result = crsr.execute(sql_command).fetchall()

    # close the connection
    connection.close()

    return False if result == [] else True

def getSecret(user):
    # connecting to the database
    connection = sqlite3.connect("website.db")
    
    # cursor
    crsr = connection.cursor()
    
    # get user Secret
    sql_command = f"""
                    SELECT secret FROM CREDS 
                    WHERE USER = \'{user}\';
                    """
    
    # execute the statement
    result = crsr.execute(sql_command).fetchone()

    # close the connection
    connection.close()
    
    if result:
        return result[0]
    return result


def getSeed(secret):
    return hashlib.sha512(secret.encode("utf-8")).hexdigest()

def getPlays(seed, limit=154):
    plays = ["Rock", "Lizard", "Spock", "Scissors", "Paper"]

    statesHash = int(seed, 16)
    return [(plays[int(x) % len(plays)], plays[(int(x) + 2) % len(plays)], plays[(int(x) + 4) % len(plays)]) for x in str(statesHash)[:limit]]