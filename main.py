from src.rsa import RSA
from src.generate_prime import GeneratePrime

def main():
    rsa = RSA()
    public_key, private_key = rsa.generate_keys()
    
    encrypted_message = rsa.OAEPencrypt("Hello World!")
    print("Encrypted message: ", encrypted_message, "\n")
    decrypted_message = rsa.OAEPdecrypt(encrypted_message)
    print("Decrypted message: ", decrypted_message)
    
    
    """
    print(f"Public key: {public_key}")
    print()
    print(f"Private key: {private_key}")
    """

if __name__ == "__main__":
    main()
