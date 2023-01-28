import random
from .miller_rabin  import MillerRabin

class GeneratePrime:
    def __init__(self) -> None:
        """
        Initialize the GeneratePrime class
        """
        self.rng = random.SystemRandom()
        self.miller_rabin = MillerRabin()

    def gen_prime(self) -> int:
        """
        Generate a random prime number using the Miller-Rabin primality test
        :return: int, a random prime number
        """
        while True:
            isprime = (self.rng.randrange(1 << 1024 - 1, 1 << 1024) << 1) + 1
            if self.miller_rabin.is_prime(isprime):
                return isprime
