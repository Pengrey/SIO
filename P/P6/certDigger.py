from cryptography import x509
import sys
import datetime
import os
# from binascii import b2a_base64 as b64e
# from binascii import a2b_base64 as b64d

def load_certificate(fname, store):
    f = open(fname, 'rb')
    pem_data = f.read()
    f.close()

    cert = x509.load_pem_x509_certificate(pem_data)
    # print(cert.serial_number)
    store[cert.subject] = cert

    # print(b64e(cert.tbs_certificate_bytes))
    # print(b64e(cert.signature))

    # print("Start Date: ", cert.not_valid_before)
    # print("End Date: ", cert.not_valid_after)

def validate(cert):
    now = datetime.datetime.now()

    if now < cert.not_valid_before:
        print("Certificate was issued to a future date")
        return False

    if cert.not_valid_after < now:
        print("Certificate expired")
        return False

    # Date: Done
    # Purpose
    # Certificate Signature
    #   tbs_signature_bytes, signature
    # Download and Check CRL or.. OCSP

    print("Certificate is valid") 
    return True

def build_chain(cert, intermidiate_ca, root_ca, chain):
    chain.append(cert)

    if cert.issuer in intermidiate_ca:
        issuer = intermidiate_ca[cert.issuer]
        return build_chain(issuer, intermidiate_ca, root_ca, chain)

    if cert.issuer in root_ca:
        issuer = root_ca[cert.issuer]
        chain.append(issuer)
        return True
    
    return False
        
store = {}
root_ca_store = {}
intermidiate_ca_store = {}

# Load Server Certificate
load_certificate(sys.argv[1], store)

# Load Intermediate CA Certificate
load_certificate(sys.argv[2], intermidiate_ca_store)

# Load ROOT CAs Certificates
for direntry in os.scandir("/etc/ssl/certs"):
    try:
        load_certificate(f'/etc/ssl/certs/{direntry.name}', root_ca_store)
    except:
        pass

print("Cert: ", len(store))
print("Intermiediate CA: ", len(intermidiate_ca_store))
print("Root CA: ", len(root_ca_store))

chain = []
cert = store[list(store)[0]]
result = build_chain(cert, intermidiate_ca_store, root_ca_store, chain)
print(result)

valid = True
for cert in chain:
    print("Subject: ",cert.subject)
    print("Issuer: ", cert.issuer)
    print()
    if not validate(cert):
        valid = False

print("Chain validity: ", valid)