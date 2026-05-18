from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from secrets import token_bytes
from Crypto.Math.Numbers import Integer

INFO_STRING = b"encryption key"

def import_go_ecdh_pubkey(pub_bytes: bytes) -> ECC.EccKey:
    if pub_bytes[0] != 0x04:
        raise ValueError("Only uncompressed points supported")

    x = Integer.from_bytes(pub_bytes[1:33])
    y = Integer.from_bytes(pub_bytes[33:65])

    return ECC.construct(
        curve="P-256",
        point_x=x,
        point_y=y
    )

def kdf(x):
    return SHA256.new(x).digest()

def encrypt(pubKey: ECC.EccKey, plaintext: bytes) -> dict:
    eph = ECC.generate(curve='p256')
    shared_point = pubKey.pointQ * eph.d

    shared_x = int(shared_point.x).to_bytes(32, 'big')

    salt = token_bytes(16)
    key = HKDF(master=shared_x, key_len=32, salt=salt, hashmod=SHA256, context=INFO_STRING)
    assert type(key) == bytes

    cipher = AES.new(mode=AES.MODE_GCM, key=key)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    x = int(eph.public_key().pointQ.x).to_bytes(32, "big")
    y = int(eph.public_key().pointQ.y).to_bytes(32, "big")
    eph_pub = b"\x04" + x + y

    return {
        'salt': salt.hex(),
        'nonce': cipher.nonce.hex(),
        'ciphertext': (ciphertext + tag).hex(),
        'eph_pub': eph_pub.hex()
    }

pubKey = import_go_ecdh_pubkey(open('pubKey.bin', 'rb').read())

print(encrypt(pubKey, b'ECIES from python to go is very easy'))
