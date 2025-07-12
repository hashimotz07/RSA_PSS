from keygen import gerador_chaves_rsa

public, private = gerador_chaves_rsa(bits=2048)
print("Chave pública (e, n):", public)
print("Chave privada (d, n):", private)
