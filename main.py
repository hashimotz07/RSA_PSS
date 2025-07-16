from keygen import gerador_chaves_rsa
from utils import serialize_key, save_key_to_pem
from rsa import cifrar_rsa_pss
from hash_utils import hash_SHA_256, hash_SHA_256_msg_codificada
from pss import generate_salt

public, private = gerador_chaves_rsa(bits=2048)
print("Chave pública (e, n):", public)
print("Chave privada (d, n):", private)

public_data = serialize_key(*public)
private_data = serialize_key(*private)

save_key_to_pem("public_key.pem", public_data, key_type="public")
save_key_to_pem("private_key.pem", private_data, key_type="private")

print("Chaves salvas com sucesso!")

texto = "oi eu gostaria de tirar 10 no trabalho pois me esforcei muito."
texto_hash = hash_SHA_256(texto)

print(f'Texto hash: {texto_hash}')
# print(f'Tamanho do hash')

salt = generate_salt()

m = b'\x00\x00\x00\x00\x00\x00\x00\x00' + texto_hash + salt

m_hash = hash_SHA_256_msg_codificada(m)

print(m_hash)