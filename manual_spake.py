from secrets import token_bytes
import ecc_ops

class Spake_A(ecc_ops.ECC):
    def __init__(self, password: bytes):
        self.__password = int.from_bytes(password, 'big')
        self.__private = int.from_bytes(token_bytes(20), 'big')

        self.__part2 = self.scalar_mult(self.__password, ecc_ops.M)
        self.__remotePart2 = self.scalar_mult(self.__password, ecc_ops.N)

        self.__part1 = self.scalar_mult(self.__private, ecc_ops.G)

    def start(self) -> bytes:
        returnData = self.point_add(self.__part1, self.__part2)
        if returnData == None:
            raise ValueError('Could not compute non zero value')
        x, y = returnData
        x = x.to_bytes(32, 'big')
        y = y.to_bytes(32, 'big')
        return x + y

    def finish(self, rawRemoteData: bytes) -> bytes:
        x, y = rawRemoteData[:32], rawRemoteData[32:]
        x = int.from_bytes(x, 'big')
        y = int.from_bytes(y, 'big')
        if self.__remotePart2 == None:
            raise ValueError('Could not compute remote part')
        to_minus = self.point_sub((x, y), self.__remotePart2)
        if to_minus == None:
            raise ValueError('Could not compute subtraction')
        shared = self.scalar_mult(self.__private, to_minus)
        if shared == None:
            raise ValueError('Could not compute shared secret')
        x, _ = shared
        x = x.to_bytes(32, 'big')
        return x

class Spake_B(ecc_ops.ECC):
    def __init__(self, password: bytes):
        self.__password = int.from_bytes(password, 'big')
        self.__private = int.from_bytes(token_bytes(20), 'big')

        self.__part2 = self.scalar_mult(self.__password, ecc_ops.N)
        self.__remotePart2 = self.scalar_mult(self.__password, ecc_ops.M)

        self.__part1 = self.scalar_mult(self.__private, ecc_ops.G)

    def start(self) -> bytes:
        returnData = self.point_add(self.__part1, self.__part2)
        if returnData == None:
            raise ValueError('Could not compute non zero value')
        x, y = returnData
        x = x.to_bytes(32, 'big')
        y = y.to_bytes(32, 'big')
        return x + y

    def finish(self, rawRemoteData: bytes) -> bytes:
        x, y = rawRemoteData[:32], rawRemoteData[32:]
        x = int.from_bytes(x, 'big')
        y = int.from_bytes(y, 'big')
        if self.__remotePart2 == None:
            raise ValueError('Could not compute remote part')
        to_minus = self.point_sub((x, y), self.__remotePart2)
        if to_minus == None:
            raise ValueError('Could not compute subtraction')
        shared = self.scalar_mult(self.__private, to_minus)
        if shared == None:
            raise ValueError('Could not compute shared secret')
        x, _ = shared
        x = x.to_bytes(32, 'big')
        return x

if __name__ == '__main__':
    spake1 = Spake_A(b'helloworld')
    spake2 = Spake_B(b'helloworld')

    spake1_pub = spake1.start()
    spake2_pub = spake2.start()

    shared1 = spake1.finish(spake2_pub)
    shared2 = spake2.finish(spake1_pub)

    assert shared1 == shared2
    print('Matrix broken')
