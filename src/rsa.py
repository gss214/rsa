from .generate_prime import GeneratePrime
from .utils import Utils

class RSA():
    """
    Class for implementing RSA encryption and decryption.
    """
    def __init__(self) -> None:
        """
        Initialize the GeneratePrime and Utils objects.
        """
        self.gen_prime = GeneratePrime()
        self.utils = Utils()

    def generate_keys(self):
        """
        Generates the public and private keys for RSA encryption.

        Returns:
            List[Tuple[int]]: A list containing two tuples, each representing a pair of public or private keys.
        """
        prime_p = self.gen_prime.gen_prime()  
        prime_q = self.gen_prime.gen_prime()  
        modulus = prime_p * prime_q
        totient = (prime_p - 1) * (prime_q - 1)
        encryption_exponent = 65537
        decryption_exponent = self.utils.extended_gcd(encryption_exponent, totient)
        public_key = [modulus, encryption_exponent]
        private_key = [modulus, decryption_exponent]

        return (public_key, private_key)
