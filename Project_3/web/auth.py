from base64 import b64encode as b64e, b64decode as b64d
from hashlib import sha256
import sys

def get_cookie(app_key, username):
    val = f'username={username}'
    cookie = b64e(val.encode()) + b"." + calculate_signature(app_key, val.encode())

    return cookie

def calculate_signature(app_key, data):
    hash = sha256()

    hash.update(app_key + data)
    h = hash.digest()
    
    return b64e(h)


def authenticate_user(app_key, request):
    cookie = request.cookies.get('auth', None)
    print(f'Cookie: {cookie}', file=sys.stderr)
    
    if cookie is None:
        print("No cookie", file=sys.stderr)
        return 'guest'

    cookie_val = cookie.split('.')
    print(cookie_val, file=sys.stderr)
    if len(cookie_val) != 2:
        print("Invalid cookie format", file=sys.stderr)
        return 'guest'

    data, sig = cookie_val
    values = {}
    try:
        data = b64d(data)
        print(data, file=sys.stderr)
    except:
        print("Invalid cookie format b64", file=sys.stderr)
        return 'guest'

    for v in data.split(b'&'):
        kv = v.split(b'=')
        if len(kv) == 2:
            try:
                values[kv[0].decode()] = kv[1].decode()
            except:
                pass
    
    test_sig = calculate_signature(app_key, data)
    print(f"Sig: {sig} TestSig: {test_sig}", file=sys.stderr)

    if test_sig.decode() != sig:
        print("Invalid signature", file=sys.stderr)
        return 'guest'
    
    return values.get('username', 'guest')
    

