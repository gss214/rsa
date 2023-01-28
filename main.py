from src.rsa import RSA

def main():
    rsa = RSA()
    public_key, private_key = rsa.generate_keys()
    print(f"Public key: {public_key}")
    print()
    print(f"Private key: {private_key}")

if __name__ == "__main__":
    main()
