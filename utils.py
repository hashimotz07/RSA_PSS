import base64

def int_to_bytes(n: int) -> bytes:
    #Converte inteiro para bytes
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def serialize_key(e_or_d: int, n: int) -> str:
    #Serializa chave como e|n ou d|n, codificado em base64
    e_bytes = int_to_bytes(e_or_d)
    n_bytes = int_to_bytes(n)
    return base64.b64encode(len(e_bytes).to_bytes(2, 'big') + e_bytes + n_bytes).decode()

def save_key_to_pem(filename: str, key_data: str, key_type: str):
    #Salva chave codificada em base64 com cabeçalhos PEM
    if key_type == "public":
        header = "-----BEGIN RSA PUBLIC KEY-----"
        footer = "-----END RSA PUBLIC KEY-----"
    elif key_type == "private":
        header = "-----BEGIN RSA PRIVATE KEY-----"
        footer = "-----END RSA PRIVATE KEY-----"
    else:
        raise ValueError("key_type deve ser 'public' ou 'private'")

    with open(filename, "w") as f:
        f.write(header + "\n")
        # Quebra em linhas de 64 caracteres
        for i in range(0, len(key_data), 64):
            f.write(key_data[i:i+64] + "\n")
        f.write(footer + "\n")

def load_key_from_pem(filename: str):
    #Lê e decodifica uma chave PEM para tupla (e, n) ou (d, n)
    with open(filename, "r") as f:
        lines = f.readlines()
        b64 = "".join(line.strip() for line in lines if not line.startswith("-----"))
        raw = base64.b64decode(b64)
        len_e = int.from_bytes(raw[:2], 'big')
        e_or_d = bytes_to_int(raw[2:2+len_e])
        n = bytes_to_int(raw[2+len_e:])
        return (e_or_d, n)
