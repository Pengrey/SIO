#!/usr/local/bin/python3

import os
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def keygen(key_len):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(key_len),
    )
    private_key_str = private_key.private_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
        
    # Generate public key
    public_key = private_key.public_key()
    public_key_str = public_key.public_bytes(   
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(private_key_str.decode('utf-8'))
    print(public_key_str.decode('utf-8'))

if __name__ == "__main__":
    keygen(sys.argv[1])