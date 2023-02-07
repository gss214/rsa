from .generate_prime import GeneratePrime
from .utils import Utils
import math
import struct
import hashlib
import os

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
        self.hash_func = hashlib.sha256
        self.k = int(1024/8)
        self.h_len = self.hash_func().digest_size

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
        
        out_extended_gcd = self.utils.extended_gcd(encryption_exponent, totient)
        decryption_exponent = out_extended_gcd[1]

        if decryption_exponent < 0: 
            decryption_exponent += totient
        
        public_key = [modulus, encryption_exponent]
        private_key = [modulus, decryption_exponent]

        return (public_key, private_key)

    def RSAEncrypt(self, encoded_message, public_key):
        cryptogram = []
        for i in encoded_message:
            # c = m^e \mod n
            cryptogram.append(pow(i, public_key[1], public_key[0]))
        return cryptogram

    def RSADecrypt(self, encoded_message, private_key):
        message = []
        for i in encoded_message:
            # m = c^d \mod n
            message.append(pow(i, private_key[1], private_key[0]))
        return message

    def form_data_block(self, l_hash, message):
        ps = bytearray()
        for _ in range(self.k - len(message) - ( 2 * self.h_len ) - 2):
            ps.append(0) 
        return l_hash + ps + b'\x01' + message

    def OAEPencrypt(self, message, public_key, label=""):
        
        label = label.encode()

        if len(message) > self.k - 2 * self.h_len - 2:
            raise ValueError("Message is too long to be encoded using OAEP.")

        # 1) hash the label using sha256
        l_hash = self.hash_func(label).digest()

        # 2) generate a padding string PS
        # 3) concatenate l_hash, ps, the single byte 0x01, and the message M
        db = self.form_data_block(l_hash, message)

        # 4) generate a random seed of length h_len
        seed = os.urandom(self.h_len)

        # 5) generate a mask of the appropriate length for the data block
        db_mask = self.mgf1(seed, self.k - self.h_len - 1, self.hash_func)

        # 6) mask the data block with the generated mask
        masked_db = bytes(self.utils.xor(db, db_mask))

        # 7) generate a mask of length hLen for the seed
        seed_mask = self.mgf1(masked_db, self.h_len, self.hash_func)
        
        # 8) mask the seed with the generated mask
        masked_seed = bytes(self.utils.xor(seed, seed_mask))

        # 9) the encoded (padded) message is the byte 0x00 concatenated with the masked_seed and masked_db
        encoded_message = b'\x00' + masked_seed + masked_db

        # 10) encrypt message with RSA
        return self.RSAEncrypt(encoded_message, public_key)

    def OAEPdecrypt(self, encoded_message, private_key, label=""):
        """
        Decode the encoded message using the OAEP method.

        Args:
            encoded_message (bytes): The encoded message to be decoded.

        Returns:
            bytes: The decoded message.
        """
        
        label = label.encode()

        # 1) decrypt message with RSA
        encoded_message = self.RSADecrypt(list(encoded_message), private_key)

        # 2) hash the label using sha256
        l_hash = self.hash_func(label).digest()
        
        if len(encoded_message) != self.k:
            raise ValueError("Encoded message has incorrect length.")

        # 3) reverse step 9: split the encoded message
        masked_seed = bytes(encoded_message[1 : self.h_len + 1])
        masked_db = bytes(encoded_message[self.h_len + 1:])

        # 4) generate the seed_mask which was used to mask the seed
        seed_mask = self.mgf1(masked_db, self.h_len, self.hash_func)

        # 5) reverse step 8: recover the seed
        seed = bytes(self.utils.xor(masked_seed, seed_mask))

        # 6) generate the db_mask which was used to mask the data block
        db_mask = self.mgf1(seed, self.k - self.h_len - 1, self.hash_func)

        # 7) reverse step 6: recover the data block
        db = bytes(self.utils.xor(masked_db, db_mask))

        # 8) verify if the decoded message is valid
        l_hash_gen = db[:self.h_len]

        if l_hash_gen != l_hash:
            raise ValueError("Decoded message has incorrect label hash.")
        
        # 9) split the message correctly
        message_start = self.h_len + db[self.h_len:].find(b'\x01') + 1
        message = db[message_start:]
        
        return message.decode()

    def mgf1(self, seed, mask_len, hash_func):
        """
        Implements the MGF1 function used in the OAEP encoding and decoding.

        Args:
            seed (bytes): The seed for the MGF1 function.
            mask_len (int): The desired length of the mask.
            hash_func (callable): The hash function to be used in MGF1.

        Returns:
            bytes: The mask generated by MGF1.
        """
        
        if mask_len > 2**32 * self.h_len: raise ValueError("Mask too long.")
        
        T = bytearray()
        for counter in range(math.ceil(mask_len / self.h_len)):
            c = struct.pack(">I", counter)
            T += hash_func(seed + c).digest()
        return T[:mask_len]