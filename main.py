from keygen import gerador_chaves_rsa
from utils import serialize_key, save_key_to_pem

public, private = gerador_chaves_rsa(bits=2048)
print("Chave pública (e, n):", public)
print("Chave privada (d, n):", private)

public_data = serialize_key(*public)
private_data = serialize_key(*private)

save_key_to_pem("public_key.pem", public_data, key_type="public")
save_key_to_pem("private_key.pem", private_data, key_type="private")

print("Chaves salvas com sucesso!")