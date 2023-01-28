import random
from .miller_rabin import MillerRabin

class GeneratePrime:
    """
    Class for generating a random prime number using Miller-Rabin primality test. Includes a random number generator and an instance of the MillerRabin class for performing the test.
    """
    def __init__(self) -> None:
        """
        Initializes GeneratePrime class with random number generator and Miller-Rabin primality test object. Generates a random 1024-bit prime number using Miller-Rabin test.
        """
        self.rng = random.SystemRandom()
        self.miller_rabin = MillerRabin()

    def gen_prime(self) -> int:
        """
        Generate a random prime number using the Miller-Rabin primality test
        
        Returns:
            int: A random prime number
        """
        while True:
            isprime = (self.rng.randrange(1 << 1024 - 1, 1 << 1024) << 1) + 1
            if self.miller_rabin.is_prime(isprime):
                return isprime
