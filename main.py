from src.rsa import RSA
from src.generate_prime import GeneratePrime
from src.utils import Utils
import hashlib
from pickle import dumps
import base64

def main():

    message = "Hello World!"
    message = message.encode()

    rsa = RSA()
    utils = Utils()
    
    # 1.a) geração de chaves (p e q primos com no mínimo de 1024 bits) 
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
    
    #print("Hash sha3: ", hash_sha3)

    # 2.b) assinatura da mensagem (cifração do hash da mensagem) 
    signature_message = rsa.OAEPencrypt(hash_sha3, public_key)

    #print("Signature message: ", signature_message)

    # 2.c) formatação do resultado (caracteres especiais e informações para verificação em BASE64)
    b64_message_encoded = base64.b64encode(dumps(signature_message))

    #print("BASE64 encoded message: ", b64_message_encoded)

if __name__ == "__main__":
    main()
