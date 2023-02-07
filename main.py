from src.rsa import RSA
from src.generate_prime import GeneratePrime
from src.utils import Utils
import hashlib

def main():
    rsa = RSA()
    utils = Utils()
    
    # 1.a) geração de chaves (p e q primos com no mínimo de 1024 bits) 
    public_key, private_key = rsa.generate_keys()
    #print("Public key: ", public_key)
    #print("Private key: ", private_key)
    
    # 1.b) cifração/decifração assimétrica RSA usando OAEP
    encrypted_message = rsa.OAEPencrypt("Hello World!", public_key)
    print("Encrypted message: ", encrypted_message, "\n")
    
    decrypted_message = rsa.OAEPdecrypt(encrypted_message, private_key)
    print("Decrypted message: ", decrypted_message)

    # 2.a) calculo de hashes da mensagem em claro (função de hash SHA-3) 
    #hash_sha3 = hashlib.sha3_256(bytearray("Hello World!", "utf-8")).digest()

    # 2.b) assinatura da mensagem (cifração do hash da mensagem) 



if __name__ == "__main__":
    main()
