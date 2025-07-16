import hashlib

def hash_SHA_256(mensagem):
    # aplica o hash SHA-256
    return hashlib.sha3_256(mensagem.encode('utf-8')).digest()

def hash_SHA_256_msg_codificada(mensagem):
    return hashlib.sha3_256(mensagem).digest()
