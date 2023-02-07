class Utils():
    """
    Class for utility functions.
    """
    def extended_gcd(self, a, b):
        """
        Computes the greatest common divisor (gcd) and the coefficients of Bezout's identity using the extended Euclidean algorithm.

        Args:
            a (int): An integer.
            b (int): An integer.

        Returns:
            Tuple[int, int, int]: A tuple containing the gcd of a and b, and the coefficients x and y of Bezout's identity.
        """
        if b == 0:
            return a, 1, 0
        else:
            gcd, x, y = self.extended_gcd(b, a % b)
            return gcd, y, x - (a // b) * y

    def xor(self, a, b):
        """
        Computs a xor operation between two strings

        Args:
            a: A string
            b: A string

        Returns:
            A string resulted of a xor operation

        """
        return [a[i] ^ b[i] for i in range(len(a))]
