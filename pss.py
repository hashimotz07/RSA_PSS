import secrets

def generate_salt(size=32):
    # gera uma sequencia de bytes aleatorios
    return secrets.token_bytes(size)