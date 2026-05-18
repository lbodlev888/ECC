p = int('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff', 16)
a = int('ffffffff00000001000000000000000000000000fffffffffffffffffffffffc', 16)
b = int('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b', 16)
n = int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 16)

G = (int('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 16), int('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', 16))

M = (61709229055687782219344352628424647386531596507379261315813478518843566432559, 43399651700267013692148409492066214468674361939146464406474584691695279811872)

N = (98031458012971070369465795029179261841266230867477002166417845678366165379913, 3544368724946236282841049099645644789675854804295951046212527731618188549095)

type Point = tuple[int, int]

class ECC:
    def to_bytes(self, P: Point):
        x, y = P

        # 32-byte little-endian y coordinate
        y_bytes = y.to_bytes(32, 'big')

        # Set sign bit of x in MSB of last byte
        if x & 1:
            y_bytes = bytearray(y_bytes)
            y_bytes[31] |= 0x80

        return bytes(y_bytes)


    def inv_mod(self, nr: int, mod: int) -> int:
        return pow(nr, mod-2, mod)

    def is_on_curve(self, P: Point) -> bool:
        x, y = P
        return (y * y - (x * x * x + a * x + b)) % p == 0

    def point_neg(self, p1: Point) -> Point:
        x, y = p1
        return (x, (-y) % p)

    def point_add(self, P: Point | None, Q: Point) -> Point:
        if P == None:
            return Q
        
        x1, y1 = P
        x2, y2 = Q

        if P == Q:
            slope = (3 * x1 * x1 + a) * self.inv_mod(2 * y1, p)
        else:
            slope = self.inv_mod(x2 - x1, p) * (y2 - y1)

        x3 = (slope * slope - x1 - x2) % p
        y3 = (slope * (x1 - x3) - y1) % p

        return (x3, y3)

    def point_sub(self, P: Point, Q: Point) -> Point:
        return self.point_add(P, self.point_neg(Q))

    def scalar_mult(self, k: int, P: Point) -> Point:
        result = None
        addend = P

        while k > 0:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        if result == None:
            raise ValueError('Could not compute this operation')
        return result

if __name__ == '__main__':
    priv_key = 42730367146922300409642536339053635974357126699797231653110462562093812963170
    ecc = ECC()
    pubKey = ecc.scalar_mult(priv_key, G)
    print(pubKey)
    print(p)
