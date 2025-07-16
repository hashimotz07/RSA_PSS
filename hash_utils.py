import hashlib

def hash_SHA_256(mensagem):
    # aplica o hash SHA-256
    return hashlib.sha256(mensagem.encode('utf-8')).hexdigest()
