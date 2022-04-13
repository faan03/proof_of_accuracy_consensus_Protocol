"""-------------------------------------------------------------------------------
                                    Zq
-------------------------------------------------------------------------------"""
import random
from Crypto.Hash import SHA512


class Zq:
    def __init__(self, q):
        self.q = q

    def __modulo(self, a, b):
        return a % b  # residuo div entera entre a y b

    def suma(self, a, b):
        r = self.__modulo((a + b), self.q)
        return r

    def resta(self, a, b):
        r = self.__modulo(a - b, self.q)
        return r

    def producto(self, a, b):
        r = self.__modulo(a * b, self.q)
        return r

    def division(self, a, b):
        invM_b = self.invMulti(b)
        r = self.__modulo(a * invM_b, self.q)
        return r

    def potencia(self, base, potencia):
        r = pow(base, potencia, self.q)
        return r

    def invMulti(self, a):
        r = self.__gcdExtended(a, self.q)[1]
        return r

    def __gcdExtended(self, a, b):
        # Base Case
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.__gcdExtended(b % a, a)
        # Update x and y using results of recursive
        # call
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def getRandomElement(self):
        return random.randint(0, self.q - 1)

    def getRandomNotZeroElement(self):
        return random.randint(1, self.q - 1)
        # return self.__modulo(int(h.digest(),16),q)

    def H(self, list):  # toma los n parametros, los pasa a binarios los suma
        sb = ""
        for l in list:
            sb = sb + bin(l)
        h = hashlib.sha256(sb.encode("utf-8")).hexdigest()
        return self.__modulo(int(h, 16), q)


"""-------------------------------------------------------------------------------
                                    Generator
-------------------------------------------------------------------------------"""


class Generator:
    def __init__(self, G, q):
        self.G = G
        self.q = q
        self.zq = Zq(q)
        self.__getGenerator()

    def __getGenerator(self):
        ##toma un elemento entre 1 y p-1
        element = self.G.getRandomElement()
        while (self.G.potencia(element, 2) == 1) or (
            self.G.potencia(element, self.q) != 1
        ):
            element = self.G.getRandomElement()
        self.g = element

    def get_g(self):
        return self.g
