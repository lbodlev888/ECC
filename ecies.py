from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from secrets import token_bytes
from base64 import b64encode as b64e, b64decode as b64d

def init_ecc_private_key(export: bool) -> ECC.EccKey:
    key = ECC.generate(curve='P-256')
    if export:
        priv_key = key.export_key(format='DER')
        pub_key = key.public_key().export_key(format='DER')
        with open('ecc_private.pem', 'wb') as f:
            f.write(priv_key)

        with open('ecc_public.pem', 'wb') as f:
            f.write(pub_key)

    return key

def encrypt(pubkey: ECC.EccKey, plaintext: bytes) -> dict:
    eph = ECC.generate(curve='P-256')
    eph_public = b64e(eph.public_key().export_key(format='DER')).decode()

    shared_point = pubkey.pointQ * eph.d

    shared_x = shared_point.x.to_bytes(32, 'big')
    shared_y = shared_point.y.to_bytes(32, 'big')

    shared_bytes = shared_x + shared_y

    salt = token_bytes(16)

    key = HKDF(shared_bytes, 32, salt, SHA256)
    if type(key) != bytes:
        raise TypeError('HKDF did not return bytes type')
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        'eph_pub': eph_public,
        'salt': b64e(salt).decode(),
        'nonce': b64e(cipher.nonce).decode(),
        'ciphertext': b64e(ciphertext).decode(),
        'tag': b64e(tag).decode()
    }

def decrypt(privkey: ECC.EccKey, encrypted_data: dict) -> bytes:
    eph_pub = ECC.import_key(b64d((encrypted_data['eph_pub'])))
    salt = b64d(encrypted_data['salt'])
    tag = b64d(encrypted_data['tag'])
    ciphertext = b64d(encrypted_data['ciphertext'])
    nonce = b64d(encrypted_data['nonce'])

    shared_point = eph_pub.pointQ * privkey.d

    shared_x = shared_point.x.to_bytes(32, 'big')
    shared_y = shared_point.y.to_bytes(32, 'big')

    shared_bytes = shared_x + shared_y


    key = HKDF(shared_bytes, 32, salt, SHA256)
    if type(key) != bytes:
        raise TypeError('HKDF did not return bytes type')
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext

if __name__ == '__main__':
    priv_key = ECC.generate(curve='p256')
    msg = b'helloworld' 
    encrypted_data = encrypt(priv_key.public_key(), msg)

    plaintext = decrypt(priv_key, encrypted_data)
    print(plaintext.decode())
