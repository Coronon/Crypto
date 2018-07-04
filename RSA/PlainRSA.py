from functools import reduce
from secrets import SystemRandom
from random import randrange, getrandbits


class RsaKeyPair(object):
    '''
    RsaKeyPair is a plain RSA class that lets you generate plain RSA Keys, encrypt data and decrypt data.

    :Parameters:\n
        :p = The first prime number\n
        :q = The second prime number\n
        :e = The public exponent\n
        :n = The public modulo\n
        :d = The private key\n
        :keylength = The keylength of a new key if p and q were not specified. If one prime number is left empty it will be generated with bitsize of keylenght/2\n
        :ignore_warning = If 'True' the security warning for a small keylength will be ignored\n
        :only_pubkey = If 'True' no p, q and d will be set. You need to specify e and n!\n

    -Functions-\n
        -quick_test = Normally called after init to check if key configuration works\n
        -encrypt = Encrypts a string after converting it to an integer with -_encrypt and returns the cipher\n
        -_encrypt = Encrypts an integer with e and n and returns the cipher\n
        -decrypt = Decrypts an integer, converts it to a string and returns the msg\n
        -_decrypt = Decrypts an integer with d and n and returns the msg\n
        -stringToNumber = Converts a string to an integer(each character to a number of len 4) and returns all characters as one integer with '1421' at the beginning to avoid leading zeros\n
        -numberToString = Converts an integer to a string after optionally removing a leading '1421' and return a string\n
        -factors = Returns the factors of a number as a set (Should only be used for generating e, for propper factorising see 'numpy'->'divisors')\n
        -get_e = This function generates an e for the defined p and q and returns it !(Dont call directly, use -return_all)!\n
        -get_d = This function generates a d for the defined n and e and return it !(Dont call directly, use -return_all)!\n
        -is_prime = Tests if a number is prime and returns 'True' or 'False' accordingly\n
        -generate_prime_candidate = Returns a prime candidate to check !(Dont call directly, use -generate_prime_number)!\n
        -generate_prime_number = Generates a prime number of the bitsize given to the function and returns it\n
        -bitcount = Returns the number of bits of an integer given to the function\n
        -return_all = Returns p, q, e, phi, n, d and nbits if the instance has a private key, e, n and nbits if it is public\n

    *Credits and license*
        *Coronon https://github.com/Coronon/Crypto
        *License: MIT


    '''

    def __init__(self,
                 p=None,
                 q=None,
                 e=None,
                 n=None,
                 d=None,
                 keylength=2048,
                 ignore_warning=False,
                 only_pubkey=False):
        if keylength < 1024 and not ignore_warning:
            raise ValueError(
                "For security reasons keylength has to be at least 1024, set 'ignore_waring' to 'True' to bypass this warning."
            )
        self.only_pubkey = only_pubkey
        self.sec = SystemRandom()

        if self.only_pubkey:
            if not e or not n:
                raise ValueError(
                    "If you want to use this only as a public key, you need to specify e and N."
                )
            self.e = e
            self.n = n
            self.nbits = self.bitcount(self.n)
            return

        if p: self.p = p
        else: self.p = self.generate_prime_number(length=keylength // 2)
        self.pbits = self.bitcount(self.p)
        pcheck = self.p
        if q: self.q = q
        else:
            while pcheck == self.p:
                pcheck = self.generate_prime_number(length=keylength // 2)
            self.q = pcheck
        self.phi = (self.p - 1) * (self.q - 1)
        if e: self.e = e
        else: self.e = self.get_e()
        if n: self.n = n
        else: self.n = self.p * self.q
        if d: self.d = d
        else: self.d = self.get_d()

        self.nbits = self.bitcount(self.n)
        self.quick_test()

    def quick_test(self):
        '''
        Normally called after init to check if key configuration works
        '''
        if (self.e * self.d) % self.phi != 1:
            raise ValueError(
                "e, d and phi value don`t match. Have you used custom ones?")
        msg = 12
        cipher = self._encrypt(msg)
        if self._decrypt(cipher) != msg:
            raise ValueError(
                "Some values dont work out. Have you used custom ones?")

    def _encrypt(self, msg):
        '''
        Encrypts an integer with e and n and returns the cipher
        '''
        if self.bitcount(msg) >= self.nbits:
            raise ValueError(
                "msg to big for this key, consider using a bigger key. (msg-bits >= {0})".
                format(self.nbits))
        return pow(msg, self.e, self.n)

    def _decrypt(self, cipher):
        '''
        Decrypts an integer with d and n and returns the msg
        '''
        if self.nbits >= 1023:
            r = self.sec.randint(
                10000000000000000000000000000000000000000000000,
                10000000000000000000000000000000000000000000000000)
            s = pow(r, self.e, self.n)
            X = (cipher * s) % self.n
            Y = pow(X, self.d, self.n)
            return (Y // r) % self.n
        else:
            return pow(cipher, self.d, self.n)

    def decrypt(self, cipher):
        '''
        Decrypts an integer, converts it to a string and returns the msg
        '''
        cipher = int(cipher)
        msg = str(self._decrypt(cipher))
        return self.numberToString(msg)

    def encrypt(self, msg):
        '''
        Encrypts a string after converting it to an integer with -_encrypt and returns the cipher
        '''
        msg = str(msg)
        toc = self.stringToNumber(msg)
        c = self._encrypt(toc)
        if not self.only_pubkey:
            if self._decrypt(c) != toc:
                raise ValueError(
                    "Message not the same after decryption, have you used custom values for the keys?"
                )
        return c

    def stringToNumber(self, msg):
        '''
        Converts a string to an integer(each character to a number of len 4) and returns all characters as one integer with '1421' at the beginning to avoid leading zeros
        '''
        ns = '1421'
        for c in str(msg):
            ns += str(ord(c)).zfill(4)
        return int(ns)

    def numberToString(self, msg):
        '''
        Converts an integer to a string after optionally removing a leading '1421' and return a string
        '''
        msg = str(msg)
        if msg[:4] == '1421': msg = msg[4:]
        cs = ''
        for n in range(len(str(msg)) // 4):
            cs += str(chr(int(str(msg)[n * 4:n * 4 + 4])))
        return cs

    def factors(self, n):
        '''
        Returns the factors of a number as a set (Should only be used for generating e, for propper factorising see 'numpy'->'divisors')
        '''
        return set(
            reduce(list.__add__, ([i, n // i]
                                  for i in range(1, int(pow(n, 0.5) + 1))
                                  if n % i == 0)))

    def get_e(self):
        '''
        This function generates an e for the defined p and q and returns it !(Dont call directly, use -return_all)!
        '''
        for i in range(3, 10001, 2):
            d = self.factors(i)
            d.discard(1)
            for j in d:
                if self.phi % j == 0:
                    break
            else:
                return i

    def get_d(self):
        '''
        This function generates a d for the defined n and e and return it !(Dont call directly, use -return_all)!
        '''
        t1 = [self.phi, self.e]
        t2 = [self.phi, 1]

        while t1[1] != 1:
            tb1 = t1[0] // t1[1]
            tb2 = tb1 * t1[1]
            tb3 = tb1 * t2[1]

            td1 = t1[0] - tb2
            td2 = t2[0] - tb3

            while td2 < 0:
                td2 += self.phi

            t1 = [t1[1], td1]
            t2 = [t2[1], td2]
        return t2[1]

    def is_prime(self, n, k=128):
        '''
        Tests if a number is prime and returns 'True' or 'False' accordingly
        '''
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False
        s = 0
        r = n - 1
        while r & 1 == 0:
            s += 1
            r //= 2
        for _ in range(k):
            a = randrange(2, n - 1)
            x = pow(a, r, n)
            if x != 1 and x != n - 1:
                j = 1
                while j < s and x != n - 1:
                    x = pow(x, 2, n)
                    if x == 1:
                        return False
                    j += 1
                if x != n - 1:
                    return False
        return True

    def generate_prime_candidate(self, length):
        '''
        Returns a prime candidate to check !(Dont call directly, use -generate_prime_number)!
        '''
        p = getrandbits(length)
        p |= (1 << length - 1) | 1
        return p

    def generate_prime_number(self, length=2048):
        '''
        Generates a prime number of the bitsize given to the function and returns it
        '''
        p = 4
        while not self.is_prime(p, 128):
            p = self.generate_prime_candidate(length)
        return p

    def bitcount(self, n):
        '''
        Returns the number of bits of an integer given to the function
        '''
        a = 1
        while 1 << a <= n:
            a <<= 1
        s = 0
        while a > 1:
            a >>= 1
            if n >= 1 << a:
                n >>= a
                s += a
        if n > 0:
            s += 1
        return s

    def return_all(self):
        '''
        Returns p, q, e, phi, n, d and nbits if the instance has a private key, e, n and nbits if it is public
        '''
        if self.only_pubkey:
            return {'e': self.e, 'n': self.n, 'nbits': self.nbits}
        return {
            'p': self.p,
            'q': self.q,
            'e': self.e,
            'phi': self.phi,
            'n': self.n,
            'd': self.d,
            'nbits': self.nbits
        }
