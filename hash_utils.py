import hashlib

def hash_SHA_256(mensagem):
    # aplica o hash SHA-256
    return hashlib.sha3_256(mensagem.encode('utf-8')).hexdigest()
