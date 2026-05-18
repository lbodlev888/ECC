from Crypto.Hash import SHA256
import ecc_ops
from Crypto.Cipher import AES
from secrets import token_bytes
from Crypto.Protocol.KDF import HKDF

ECC = ecc_ops.ECC()

def encrypt(pubKey: ecc_ops.Point, plaintext: bytes) -> dict:
    eph_priv = int.from_bytes(token_bytes(20), 'big')
    eph_pub = ECC.scalar_mult(eph_priv, ecc_ops.G)

    shared_point = ECC.scalar_mult(eph_priv, pubKey)

    if shared_point == None:
        raise ValueError('Could not compute shared secret')

    x = shared_point[0].to_bytes((shared_point[0].bit_length() + 7) // 8, 'big')
    y = shared_point[1].to_bytes((shared_point[1].bit_length() + 7) // 8, 'big')
    shared_secret = x + y
    salt = token_bytes(16)

    master_key = HKDF(shared_secret, 32, salt, SHA256)

    assert type(master_key) == bytes

    cipher = AES.new(master_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        'salt': salt.hex(),
        'ciphertext': ciphertext.hex(),
        'tag': tag.hex(),
        'nonce': cipher.nonce.hex(),
        'eph_pub': eph_pub
    }

def decrypt(privKey: int, encrypted_data: dict) -> bytes:
    eph_pub = encrypted_data['eph_pub']
    salt = bytes.fromhex(encrypted_data['salt'])
    ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
    nonce = bytes.fromhex(encrypted_data['nonce'])
    tag = bytes.fromhex(encrypted_data['tag'])

    shared_point = ECC.scalar_mult(privKey, eph_pub)

    if shared_point == None:
        raise ValueError('Could not compute shared secret')

    x = shared_point[0].to_bytes((shared_point[0].bit_length() + 7) // 8, 'big')
    y = shared_point[1].to_bytes((shared_point[1].bit_length() + 7) // 8, 'big')
    shared_secret = x + y

    master_key = HKDF(shared_secret, 32, salt, SHA256)

    assert type(master_key) == bytes

    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext

if __name__ == '__main__':
    privKey = int.from_bytes(token_bytes(20), 'big')
    pubKey = ECC.scalar_mult(privKey, ecc_ops.G)
    assert pubKey != None
    msg = b'helloworld'
    encrypted_data = encrypt(pubKey, msg)
    plaintext = decrypt(privKey, encrypted_data)
    print(plaintext.decode())
