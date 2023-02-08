import random

class MillerRabin:
    def __init__(self) -> None:
        """
        Initializes the MillerRabin object
        """
        self.rng = random.SystemRandom()

    def single_test(self, number: int, witness: int) -> bool:
        """
        Perform a single test of the Miller-Rabin primality test
        
        Args:
            number (int): The number to be tested for primality.
            witness (int): A random integer in the range [2, number-1].
        
        Returns:
            bool: True if number is probably prime, False otherwise
        """
        exp, rem = number - 1, 0
        while not exp & 1:  # check if exp is even
            exp >>= 1
            rem += 1
        x = pow(witness, exp, number)
        if x == 1 or x == number - 1:
            return True
        for _ in range(rem - 1):
            x = pow(x, 2, number)
            if x == number - 1:
                return True
        return False

    def is_prime(self, number: int, k=40) -> bool:
        """
        Test a number:param rimality using the Miller-Rabin primality test

        Args:
            number (int): The number to be tested for primality
            k (int, optinal): The number of iterations of the single_test function to perform. Default is 40.
        
        Returns
            bool: True if number is probably prime, False otherwise
        """
        if number <= 1: return False
        if number <= 3: return True
        if number % 2 == 0 or number % 3 == 0: return False

        for _ in range(k):
            witness = self.rng.randrange(2, number - 1)
            if not self.single_test(number, witness): return False
        return True
