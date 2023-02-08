from src.rsa import RSA
import hashlib
import base64
from pickle import dumps, loads

def main():

    message = input("Insira uma mensagem para ser cifrada: ").encode()
    
    rsa = RSA()
    
    # 1.a) geração de chaves (p e q primos com no mínimo de 1024 bits) 
    print("\nGerando as chaves publica e privada...")
    public_key, private_key = rsa.generate_keys()
    
    #print("Public key: ", public_key)
    #print("Private key: ", private_key)
    
    # 1.b) cifração/decifração assimétrica RSA usando OAEP
    encrypted_message = rsa.OAEPencrypt(message, public_key)
    
    #print("Encrypted message: ", encrypted_message, "\n")
    
    decrypted_message = rsa.OAEPdecrypt(encrypted_message, private_key)
    
    #print("Decrypted message: ", decrypted_message)
    
    # 2.a) calculo de hashes da mensagem em claro (função de hash SHA-3) 
    hash_sha3 = hashlib.sha3_256(message).digest()
    print("Gerando o hash sha3 da menssagem...")
    #print("Hash sha3: ", hash_sha3)

    # 2.b) assinatura da mensagem (cifração do hash da mensagem) 
    signature_message = rsa.OAEPencrypt(hash_sha3, public_key)
    print("Cifrando o hash com RSA-OAEP...")
    
    #print("Signature message: ", signature_message)

    # 2.c) formatação do resultado (caracteres especiais e informações para verificação em BASE64)
    b64_message_encoded = base64.b64encode(dumps(signature_message))
    print("Codificando em base64...")
    #print("BASE64 encoded message: ", b64_message_encoded)

    # 3.a) Parsing do documento assinado e decifração da mensagem (de acordo com a formatação usada, no caso BASE64) 
    b64_message_decoded = base64.b64decode(b64_message_encoded)
    signature_message = loads(b64_message_decoded)
    print("---------------\nDecodificando base64...")

    # 3.b) Decifração da assinatura (decifração do hash) 
    decrypted_hash = rsa.OAEPdecrypt(signature_message, private_key)
    print("Decodificando o hash da mensagem com RSA-OEAP...")

    # 3.c) Verificação (cálculo e comparação do hash do arquivo) 
    
    # Mensagem modificada
    #message = "Outra mensagem".encode()
    hash_sha3_file = hashlib.sha3_256(message).digest()
    
    if hash_sha3_file == decrypted_hash:
        print("Verificação realizada com sucesso")
    else:
        print("Falha na verificação")


if __name__ == "__main__":
    main()
