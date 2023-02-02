from time import time
from struct import pack
from hashlib import sha1, sha256
from pk_signed_mpi_with_libgcrypt import PK_libgcrypt
from card_const import KEY_ATTRIBUTES_ECDH_SECP256K1, KEY_ATTRIBUTES_ECDSA_SECP256K1
lg_secp256k1 = PK_libgcrypt(32, "secp256k1")

class PK_Crypto(object):
    @staticmethod
    def pk_from_pk_info(pk_info):
        return pk_info[5:]

    @staticmethod
    def compute_digestinfo(msg):
        return sha256(msg).digest()

    @staticmethod
    def enc_data(enc_info):
        return b'\xa6\x46\x7f\x49\x43\x86\x41' + enc_info[1]

    @staticmethod
    def enc_check(enc_info, s):
        point = enc_info[0]
        # Gnuk returns point, instead of X
        if len(s) == len(point):
            return point == s
        else:
            # It's 04 || X || Y, extract X
            return point[1:33] == s


    def __init__(self, keyno=None, pk_info=None, data=None):
        if keyno == None:
            # Just for name space
            return

        self.keyno = keyno
        self.for_encryption = (self.keyno == 1)
        self.timestamp = pack('>I', int(time()))
        if pk_info:
            # Public part only (no private data) from card
            self.q = pk_info[5:]
        else:
            # Private part (in big endian)
            self.d = data[0]
            self.q = data[1]
        self.fpr = self.calc_fpr()

    def calc_fpr(self):
        m_len = 6 + 2 + 65
        ver = b'\x04'
        algo = b'\x12' if self.for_encryption else b'\x16'
        m = b'\x99' + pack('>H', m_len) + ver + self.timestamp + algo \
            + pack('>H', 512+3) + self.q
        return sha1(m).digest()

    def build_privkey_template(self, is_yubikey):
        openpgp_keyno = self.keyno + 1
        if openpgp_keyno == 1:
            keyspec = b'\xb6'
        elif openpgp_keyno == 2:
            keyspec = b'\xb8'
        else:
            keyspec = b'\xa4'
        key_template = b'\x92\x20'
        exthdr = keyspec + b'\x00' + b'\x7f\x48' + b'\x02' + key_template
        suffix = b'\x5f\x48' + b'\x20'
        return b'\x4d' + b'\x2a' + exthdr + suffix + self.d

    def compute_signature(self, digestinfo):
        return lg_secp256k1.call_pk_sign(self.d, digestinfo)

    def verify_signature(self, digestinfo, sig):
        return lg_secp256k1.call_pk_verify(self.q, digestinfo, sig)

    def encrypt(self, plaintext):
        # Do ECDH
        return lg_secp256k1.call_pk_encrypt(self.q, plaintext)

    def get_fpr(self):
        return self.fpr

    def get_timestamp(self):
        return self.timestamp

    def get_pk(self):
        return self.q

key = [ None, None, None ]

# We don't have definitive test vectors for secp256k1

# Private key values are from
# https://github.com/bitcoinjs/tiny-secp256k1/
# tests/fixtures/points.json

secp256k1_data0 = (
    b'\xb1\x12\x1e\x40\x88\xa6\x6a\x28\xf5\xb6\xb0\xf5\x84\x49\x43\xec'
    b'\xd9\xf6\x10\x19\x6d\x7b\xb8\x3b\x25\x21\x4b\x60\x45\x2c\x09\xaf',
    b'\x04'
    b'\xb0\x7b\xa9\xdc\xa9\x52\x3b\x7e\xf4\xbd\x97\x70\x3d\x43\xd2\x03'
    b'\x99\xeb\x69\x8e\x19\x47\x04\x79\x1a\x25\xce\x77\xa4\x00\xdf\x99'
    b'\x8f\x04\x0d\xc5\x12\xf1\xfa\xd4\x3c\x6f\x93\x4a\x7c\xd9\x0c\xd1'
    b'\x68\x4e\x60\xe7\x04\x9e\x63\x15\xc9\x88\xcc\x78\xcc\x38\x29\x54')

secp256k1_data1 = (
    b'\x07\x05\xe4\xb4\x9e\xa2\x54\x78\xd6\x0b\xa7\x28\x7c\xf2\xcc\x02'
    b'\x0c\x07\x4d\xd9\x7d\x47\x8c\x7f\x84\xa3\xcf\xba\xb8\xc3\x76\xe6',
    b'\x04'
    b'\x45\x54\x28\x85\x28\xe2\xc4\xf7\x61\x82\x62\x55\x48\x2f\x20\xab'
    b'\xe3\xd7\xa8\xca\xf7\x47\xf2\x17\x09\x84\x11\x0b\x2f\x64\x54\x67'
    b'\x77\xfa\x52\xf2\x70\x6c\xd8\xc3\x0f\x03\x01\x94\x39\x69\xb4\x46'
    b'\x49\x40\x58\x18\xda\x26\x69\xd0\xf8\x21\xaf\x31\x59\x73\xfa\xa1'
)

secp256k1_data2 = (
    b'\xbd\x66\x07\x4d\xae\x02\x76\xb2\x9d\xd5\xd1\x13\x6f\x53\x29\x3e'
    b'\x68\xea\xc9\x4c\xeb\x82\xa2\xd2\x26\x64\x11\xb2\x2e\xc0\xf5\x9c',
    b'\x04'
    b'\x69\xe3\x3b\x06\x24\x0f\xfd\x20\x46\x79\x20\xfd\xb9\xa6\x20\x89'
    b'\x56\x83\x27\xfe\x66\x8e\xb2\xd1\x7c\xb0\x2b\x8c\xe8\xe6\x08\xa5'
    b'\xc7\xdd\x47\xaa\x62\xc7\x8e\xff\xaf\x82\xc4\xda\x7f\xd3\x93\x45'
    b'\xcb\x7a\xd0\x5a\xd3\x2b\xcc\xd4\xa5\xe9\x56\x7b\x2d\x11\xe2\x4b'
)

key[0] = PK_Crypto(0, data=secp256k1_data0)
key[1] = PK_Crypto(1, data=secp256k1_data1)
key[2] = PK_Crypto(2, data=secp256k1_data2)

PLAIN_TEXT0=b"In this test, we verify card generated result by libgcrypt."
PLAIN_TEXT1=b"Signature is non-deterministic (it uses nonce K internally)."
PLAIN_TEXT2=b"We don't use secp256k1 test vectors (it specifies K of ECDSA)."
PLAIN_TEXT3=b"NOTE: Our test is not for ECDSA implementation itself."

ENCRYPT_TEXT0 = sha256(b"!encrypt me please").digest()
ENCRYPT_TEXT1 = sha256(b"!!!encrypt me please, another").digest()
ENCRYPT_TEXT2 = sha256(b"!encrypt me please, the other").digest()

test_vector = {
    'sign_0' : PLAIN_TEXT0,
    'sign_1' : PLAIN_TEXT1,
    'auth_0' : PLAIN_TEXT2,
    'auth_1' : PLAIN_TEXT3,
    'decrypt_0' : ENCRYPT_TEXT0,
    'decrypt_1' : ENCRYPT_TEXT1,
    'encrypt_0' : ENCRYPT_TEXT2,
}

secp256k1_pk = PK_Crypto()
secp256k1_pk.test_vector = test_vector
secp256k1_pk.key_list = key
secp256k1_pk.key_attr_list = [KEY_ATTRIBUTES_ECDSA_SECP256K1, KEY_ATTRIBUTES_ECDH_SECP256K1, KEY_ATTRIBUTES_ECDSA_SECP256K1]
secp256k1_pk.PK_Crypto = PK_Crypto
