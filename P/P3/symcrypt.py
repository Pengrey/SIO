#!/usr/local/bin/python3

import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_file(infile, outfile, key, algo):
    if not os.path.exists(infile):
        print(f"Infile {infile} not found")
        return
    
    if os.path.exists(outfile):
        r = input(f"Overwrite outfile: {outfile}")
        if r.upper() == "Y":
            return

    if algo not in ['AES', 'ChaCha20']:
        print(f"Invalid algorithm {algo}")
        return

    if algo == 'AES':
        cipher = Cipher(algorithms.AES(key), modes.ECB())
    elif algo == 'ChaCha20':
        cipher = Cipher(algorithms.ChaCha20(key), modes.ECB())
    else:
        print(f"Invalid algorithm {algo}")
        return
    
    fin = open(infile,'rb')
    fout= open(outfile,'wb')

    encryptor = cipher.encryptor()
    while True:
        text = fin.read(16)
        if len(text) != 16:
            missing_length = 16 - len(text)
            text += bytes([missing_length]*missing_length)
            cgram = encryptor.update(text) + encryptor.finalize()
            fout.write(cgram)
            break

        cgram = encryptor.update(text)
        fout.write(cgram)
    
    fin.close()
    fout.close()
    print("File encrypted")

def decrypt_file(infile, outfile, key, algo):
    if not os.path.exists(infile):
        print(f"Infile {infile} not found")
        return
    
    if os.path.exists(outfile):
        r = input(f"Overwrite outfile: {outfile}")
        if r.upper() == "Y":
            return

    if algo not in ['AES', 'ChaCha20']:
        print(f"Invalid algorithm {algo}")
        return

    if algo == 'AES':
        iv=secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.ECB())
    elif algo == 'ChaCha20':
        cipher = Cipher(algorithms.ChaCha20(key), modes.ECB())
    else:
        print(f"Invalid algorithm {algo}")
        return
    
    fin = open(infile,'rb')
    fout= open(outfile,'wb')

    decryptor = cipher.decryptor()

    total_bytes = os.path.getsize(infile)
    read_bytes = 0
    while True:
        cgram = fin.read(16)
        read_bytes += len(cgram)
        if read_bytes == total_bytes:
            text = decryptor.update(cgram)
            padding = text[-1]
            text = text[0:16 - padding]
            fout.write(text)
            break
        text = decryptor.update(cgram)
        fout.write(text)
    
    fin.close()
    fout.close()
    print("File decrypted")


if __name__ == "__main__":
    key = os.urandom(16)
    print(key)
    encrypt_file(sys.argv[1], sys.argv[2], key, sys.argv[3])
    decrypt_file(sys.argv[2], sys.argv[2]+".decrypted", key, sys.argv[3])