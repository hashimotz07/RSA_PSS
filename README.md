# RSA_PSS - Sistema de Assinatura de Arquivos

Este script implementa um sistema completo de assinatura digital usando o padrão RSA-PSS.

### **Recursos**

  * **Geração de Chaves**: Cria um par de chaves RSA (pública e privada) de 2048 bits e as salva em formato PEM.
  * **Assinatura de Arquivos**: Assina qualquer arquivo usando a chave privada, gerando um arquivo de assinatura `.sig`.
  * **Verificação de Assinatura**: Verifica a autenticidade e a integridade de um arquivo usando o arquivo original, a assinatura e a chave pública.

### **Como Usar**

Execute os comandos no seu terminal.

1.  **Gerar Chaves**
    Este comando cria os arquivos `private_key.pem` e `public_key.pem`.

    ```bash
    python main.py gerar
    ```

2.  **Assinar um Arquivo**
    Crie um arquivo de exemplo, por exemplo, `mensagem.txt`. Depois, use o comando abaixo para assiná-lo. Ele irá gerar `mensagem.sig`.

    ```bash
    python main.py assinar mensagem.txt --chave private_key.pem
    ```

3.  **Verificar a Assinatura**
    Use o arquivo original, o arquivo de assinatura e a chave pública para verificar.

    ```bash
    python main.py verificar mensagem.txt mensagem.sig --chave public_key.pem
    ```