import ecc_ops
from Crypto.Hash import SHA256, HMAC
from secrets import token_bytes

ECC = ecc_ops.ECC()

def deterministic_k(hash: bytes, privKey: int) -> int:
    hmac = HMAC.new(privKey.to_bytes((privKey.bit_length() + 7) // 8), digestmod=SHA256)
    hmac.update(hash)
    k = int.from_bytes(hmac.digest(), 'big')
    return k

def sign(privKey: int, message: bytes) -> tuple[int, int]:
    hash_obj = SHA256.new()
    hash_obj.update(message)
    hash = hash_obj.digest()
    hash_int = int.from_bytes(hash)

    k = deterministic_k(hash, privKey)

    k_point = ECC.scalar_mult(k, ecc_ops.G)

    if k_point == None:
        raise ValueError('Could not compute signature')

    r = k_point[0] % ecc_ops.n

    if r == 0:
        raise ValueError('R=0 Repeat the process')

    s = (ECC.inv_mod(k, ecc_ops.n) * (hash_int + privKey*r)) % ecc_ops.n

    return (r, s)

def verify(pubKey: ecc_ops.Point, signature: tuple[int, int], message: bytes) -> bool:
    r, s = signature

    hash_obj = SHA256.new()
    hash_obj.update(message)
    hash_int = int.from_bytes(hash_obj.digest())

    s_inv = ECC.inv_mod(s, ecc_ops.n)

    k_point = ECC.point_add(ECC.scalar_mult(hash_int * s_inv, ecc_ops.G), ECC.scalar_mult(r * s_inv, pubKey))

    if k_point == None:
        raise ValueError('Could not recover point R')

    return k_point[0] == r

if __name__ == '__main__':
    privKey = int.from_bytes(token_bytes(110), 'big') % ecc_ops.n
    print(privKey.bit_length())
    open('priv.int', 'w').write(str(privKey))
    pubKey = ECC.scalar_mult(privKey, ecc_ops.G)

    assert pubKey != None

    msg = b'helloworld'

    signature = sign(privKey, msg)

    print('Signature good' if verify(pubKey, signature, msg) else 'Invalid signature')
