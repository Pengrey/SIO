# Project 2 - Authentication

This project was developed in the context of [Security of Information and Organizations](https://www.ua.pt/en/uc/4143) curricular unit, part of the Computer Science Bachelor at [Aveiro University](https://www.ua.pt/). It was lectured by [João Paulo Barraca](https://www.ua.pt/en/p/10333322) during 2021/2022 school year.

## Description

For this project, the focus is on the implementation of robust authentication protocols. For this, we developed a new protocol and a related web application to explore it.
The web application consists of a login/registration page about the TV series "Big Bang Theory" and another page with content about the respective series, which can be accessed the login/registration is completed successfully.
The protocol used for login authentication consists of sending a challenge (Derived from the user's credentials) from the web application to the uap and obtaining its response from the uap to the web application for N iterations. If the uap returns the correct answer to the challenge for all N iterations the user is logged in, otherwise, they aren't.

## How to run

### Run web application:

```bash
cd app_auth
python3 -m venv ./venv
source ./venv/bin/activate
pip install -r requirements.txt
flask run
```

### Run uap:

```bash
cd uap
python3 -m venv ./venv
source ./venv/bin/activate
pip install -r requirements.txt
python3 uap.py
```

## How to set up accounts to test with

### UAP

! Website *must* be this
! The username may not be 'teste', read Notice below

```
website: bazinga 
username: teste
password: <anything>
```

### Webapp

! The username may not be 'teste', read Notice below

```
email: <anything>
username: teste
password: <anything>
```

### Notice:

For testing purposes, the web app has only the public key for the user with the username “teste”, for other user registrations a public key will need to be manually added, for each new user. To test the authentication mechanism, please register the user with the name “teste” or generate a new key pair with at least with 2048 bits for this user. Please store the private key with the name \<username>.pkey in the uap/keyring folder, and the public key store with the name \<username>.key in the app_auth/Keychain folder.

## Technology stack

The code for this project was developed in HTML, CSS and JS for the web application, and Python for the backend logic. We used Flask to connect the backend with the frontend, with communication with the uap via sockets and SQLite for the database.

## Notes

For more information on the inner workings of this project, please check the attached Documentation pdf.
## Authors

[Camila Fonseca](https://github.com/Inryatt), 97880, LEI

[Diana Oliveira](https://github.com/DianaSiso), 98607, LEI

[Miguel Ferreira](https://github.com/MiguelF07), 98599, LEI

[Rodrigo Lima](https://github.com/Pengrey), 98475, LEI
