from keygen import gerador_chaves_rsa
from utils import serialize_key, save_key_to_pem,int_to_bytes
from rsa import cifrar_rsa_pss
from hash_utils import hash_SHA_256, hash_SHA_256_msg_codificada
from pss import generate_salt
from rsa import pss_pad
import verify
import base64

open("log.txt","w")

print("Olhe log.txt para ver o fluxo do codigo")
log = open("log.txt","a")


public, private = gerador_chaves_rsa(bits=2048)
e, n = public
d, m = private
log.write(f"Chave publica ({e}, {n}):\n")
log.write(f"Chave privada ({d}, {m}):\n")

public_data = serialize_key(*public)
private_data = serialize_key(*private)

save_key_to_pem("public_key.pem", public_data, key_type="public")
save_key_to_pem("private_key.pem", private_data, key_type="private")

log.write("Chaves salvas com sucesso!\n")

msg = "oi eu gostaria de tirar 10 no trabalho pois me esforcei muito."
log.write(f"Mensagem original: {msg}\n")
msg = msg.encode('utf-8')

salt = generate_salt(32)
log.write(f"salt: {salt}")


em_len = (n.bit_length() + 7) // 8
EM = pss_pad(msg, salt, em_len, n)

EM_int = int.from_bytes(EM, byteorder='big')
assinatura_int = pow(EM_int, d, n)
assinatura_bytes = int_to_bytes(assinatura_int)

assinatura_b64 = base64.b64encode(assinatura_bytes).decode()


with open("assinatura.sig", "w") as f:
    f.write("-----BEGIN SIGNATURE-----\n")
    for i in range(0, len(assinatura_b64), 64):
        f.write(assinatura_b64[i:i+64] + "\n")
    f.write("-----END SIGNATURE-----\n")

log.write("Assinatura gerada com sucesso")


with open("assinatura.sig", "r") as f:
    assinatura_b64 = ''.join(
        line.strip() for line in f if not line.startswith("-----"))


chave_publica = verify.load_key_from_pem("public_key.pem")

if verify.verificar_assinatura(msg, assinatura_b64, chave_publica):
    print("Assinatura VÁLIDA ✅")
else:
    print("Assinatura INVÁLIDA ❌")