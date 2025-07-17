from utils import load_key_from_pem, bytes_to_int, int_to_bytes
import base64
import hashlib
from rsa import mgf1 

def verificar_assinatura(msg: bytes, assinatura_b64: str, chave_publica: tuple) -> bool:
    e, n = chave_publica
    em_len = (n.bit_length() + 7) // 8
    h_len = hashlib.sha3_256().digest_size

    # 1. Decodifica a assinatura e decifra
    assinatura_bytes = base64.b64decode(assinatura_b64)
    assinatura_int = bytes_to_int(assinatura_bytes)
    EM_int = pow(assinatura_int, e, n)
    EM = int_to_bytes(EM_int).rjust(em_len, b'\x00')  # garante em_len bytes

    # 2. Verifica terminador 0xbc
    if EM[-1] != 0xbc:
        print("Terminator 0xbc inválido")
        return False

    # 3. Extrai partes
    maskedDB = EM[:em_len - h_len - 1]
    H = EM[em_len - h_len - 1:-1]

    # 4. Limpa bits extras
    em_bits = n.bit_length()
    unused_bits = 8 * em_len - em_bits
    if unused_bits > 0:
        maskedDB = bytes([maskedDB[0] & (0xFF >> unused_bits)]) + maskedDB[1:]

    # 5. Recria DB = maskedDB XOR MGF1(H)
    dbMask = mgf1(H, len(maskedDB), hashlib.sha3_256)
    DB = bytes(x ^ y for x, y in zip(maskedDB, dbMask))

    # 6. Verifica estrutura de DB = PS || 0x01 || salt
    ps_end = DB.find(b'\x01')
    if ps_end == -1:
        print("DB não contém 0x01")
        return False

    salt = DB[ps_end + 1:]
    if len(salt) != 32:
        print("Salt de tamanho inválido")
        return False

    # 7. Recalcula mHash = Hash(mensagem)
    mHash = hashlib.sha3_256(msg).digest()

    # 8. Recria M' = 0x00..00 || mHash || salt
    m_prime = b'\x00' * 8 + mHash + salt
    H_prime = hashlib.sha3_256(m_prime).digest()

    # 9. Compara H e H'
    return H == H_prime
