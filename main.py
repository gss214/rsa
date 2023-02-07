from src.rsa import RSA
from src.generate_prime import GeneratePrime

def main():
    rsa = RSA()
    
    # 1.a) geração de chaves (p e q primos com no mínimo de 1024 bits) 
    public_key, private_key = rsa.generate_keys()
    print("Public key: ", public_key)
    print("Private key: ", private_key)
    
    # 1.b) cifração/decifração assimétrica RSA usando OAEP.
    encrypted_message = rsa.OAEPencrypt("Hello World!")
    print("Encrypted message: ", encrypted_message, "\n")
    decrypted_message = rsa.OAEPdecrypt(encrypted_message)
    print("Decrypted message: ", decrypted_message)

    

if __name__ == "__main__":
    main()
