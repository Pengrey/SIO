#!/bin/bash

# Just to test. Do not use in production!
cd /app
python3 app.py

# 
#gunicorn --bind 0.0.0.0:5000 wsgi:app
