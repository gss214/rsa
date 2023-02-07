from src.rsa import RSA
from src.generate_prime import GeneratePrime

def main():
    rsa = RSA()
    public_key, private_key = rsa.generate_keys()
    opa = rsa.OAEPencrypt("aaaaaaaaaaaaaaaaaaa!", "", public_key)
    print(opa)
    print()
    pao = rsa.OAEPdecrypt(opa, '', private_key)
    print(pao)
    """
    print(f"Public key: {public_key}")
    print()
    print(f"Private key: {private_key}")
    """

if __name__ == "__main__":
    main()
