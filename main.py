import argparse
import base64
import sys
from keygen import gerador_chaves_rsa
from rsa import pss_pad
from utils import serialize_key, save_key_to_pem, load_key_from_pem, int_to_bytes
from pss import generate_salt
import verify

def gerar_chaves(bits=2048):
    """
    Gera um par de chaves RSA (pública e privada) e salva em arquivos PEM.
    """
    try:
        public, private = gerador_chaves_rsa(bits=bits)
        
        public_data = serialize_key(*public)
        private_data = serialize_key(*private)
        
        save_key_to_pem("public_key.pem", public_data, key_type="public")
        save_key_to_pem("private_key.pem", private_data, key_type="private")
        
        print("✅ Chaves 'public_key.pem' e 'private_key.pem' geradas com sucesso!")
    except Exception as e:
        print(f"❌ Erro ao gerar chaves: {e}", file=sys.stderr)
        sys.exit(1)

def assinar_arquivo(caminho_arquivo, caminho_chave_privada, caminho_saida):
    """
    Assina um arquivo usando uma chave privada e salva a assinatura.
    """
    try:
        d, n = load_key_from_pem(caminho_chave_privada)

        with open(caminho_arquivo, "rb") as f:
            mensagem_bytes = f.read()
        
        salt = generate_salt(32) 
        em_len = (n.bit_length() + 7) // 8
        EM = pss_pad(mensagem_bytes, salt, em_len, n)
        em_int = int.from_bytes(EM, byteorder='big')
        assinatura_int = pow(em_int, d, n)
        assinatura_bytes = int_to_bytes(assinatura_int)
    
        assinatura_b64 = base64.b64encode(assinatura_bytes).decode('utf-8')

        # Salva a assinatura no formato PEM
        with open(caminho_saida, "w") as f:
            f.write("-----BEGIN SIGNATURE-----\n")
            for i in range(0, len(assinatura_b64), 64):
                f.write(assinatura_b64[i:i+64] + "\n")
            f.write("-----END SIGNATURE-----\n")
        
        print(f"✒️ Arquivo '{caminho_arquivo}' assinado com sucesso. Assinatura salva em '{caminho_saida}'.")

    except FileNotFoundError:
        print(f"❌ Erro: Arquivo '{caminho_arquivo}' ou '{caminho_chave_privada}' não encontrado.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Erro durante a assinatura: {e}", file=sys.stderr)
        sys.exit(1)

def verificar_arquivo(caminho_arquivo, caminho_assinatura, caminho_chave_publica):
    """
    Verifica a assinatura de um arquivo usando a chave pública.
    """
    try:

        chave_publica = load_key_from_pem(caminho_chave_publica)

        with open(caminho_arquivo, "rb") as f:
            mensagem_bytes = f.read()

        with open(caminho_assinatura, "r") as f:
            assinatura_b64 = ''.join(line.strip() for line in f if not line.startswith("-----"))

        if verify.verificar_assinatura(mensagem_bytes, assinatura_b64, chave_publica):
            print("Assinatura VÁLIDA ✅")
        else:
            print("Assinatura INVÁLIDA ❌")

    except FileNotFoundError:
        print(f"❌ Erro: Um dos arquivos não foi encontrado.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Erro durante a verificação: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    """
    Função principal para analisar os argumentos da linha de comando.
    """
    parser = argparse.ArgumentParser(
        description="Sistema de assinatura de arquivos usando RSA-PSS.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', required=True, help='Comando a ser executado')

    parser_gerar = subparsers.add_parser('gerar', help='Gera um novo par de chaves RSA (pública e privada).')
    parser_gerar.set_defaults(func=lambda args: gerar_chaves())

    parser_assinar = subparsers.add_parser('assinar', help='Assina um arquivo usando uma chave privada.')
    parser_assinar.add_argument('arquivo', help='Caminho para o arquivo a ser assinado.')
    parser_assinar.add_argument('--chave', required=True, help='Caminho para o arquivo da chave privada (.pem).')
    parser_assinar.add_argument('--saida', help='Nome do arquivo de saída para a assinatura. Padrão: [arquivo].sig')
    parser_assinar.set_defaults(func=lambda args: assinar_arquivo(
        args.arquivo, 
        args.chave, 
        args.saida or f"{args.arquivo}.sig"
    ))

    parser_verificar = subparsers.add_parser('verificar', help='Verifica a assinatura de um arquivo.')
    parser_verificar.add_argument('arquivo', help='Caminho para o arquivo original.')
    parser_verificar.add_argument('assinatura', help='Caminho para o arquivo de assinatura (.sig).')
    parser_verificar.add_argument('--chave', required=True, help='Caminho para o arquivo da chave pública (.pem).')
    parser_verificar.set_defaults(func=lambda args: verificar_arquivo(
        args.arquivo, 
        args.assinatura, 
        args.chave
    ))

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    args.func(args)

if __name__ == '__main__':
    main()