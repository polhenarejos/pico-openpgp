from time import time
from struct import pack
from hashlib import sha1, sha256
from pk_signed_mpi_with_libgcrypt import PK_libgcrypt
from card_const import KEY_ATTRIBUTES_ECDH_BRAINPOOLP256R1, KEY_ATTRIBUTES_ECDSA_BRAINPOOLP256R1
lg_bp256 = PK_libgcrypt(32, "brainpoolP256r1")


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
        return lg_bp256.call_pk_sign(self.d, digestinfo)

    def verify_signature(self, digestinfo, sig):
        return lg_bp256.call_pk_verify(self.q, digestinfo, sig)

    def encrypt(self, plaintext):
        # Do ECDH
        return lg_bp256.call_pk_encrypt(self.q, plaintext)

    def get_fpr(self):
        return self.fpr

    def get_timestamp(self):
        return self.timestamp

    def get_pk(self):
        return self.q

key = [ None, None, None ]

# https://datatracker.ietf.org/doc/html/rfc6932#appendix-A.2

bp256_data0 = (
    b'\x04\x1e\xb8\xb1\xe2\xbc\x68\x1b\xce\x8e\x39\x96\x3b\x2e\x9f\xc4'
    b'\x15\xb0\x52\x83\x31\x3d\xd1\xa8\xbc\xc0\x55\xf1\x1a\xe4\x96\x99',
    b'\x04'
    b'\x78\x02\x84\x96\xb5\xec\xaa\xb3\xc8\xb6\xc1\x2e\x45\xdb\x1e\x02'
    b'\xc9\xe4\xd2\x6b\x41\x13\xbc\x4f\x01\x5f\x60\xc5\xcc\xc0\xd2\x06'
    b'\xa2\xae\x17\x62\xa3\x83\x1c\x1d\x20\xf0\x3f\x8d\x1e\x3c\x0c\x39'
    b'\xaf\xe6\xf0\x9b\x4d\x44\xbb\xe8\x0c\xd1\x00\x98\x7b\x05\xf9\x2b'
)

bp256_data2 = (
    b'\x06\xf5\x24\x0e\xac\xdb\x98\x37\xbc\x96\xd4\x82\x74\xc8\xaa\x83'
    b'\x4b\x6c\x87\xba\x9c\xc3\xee\xdd\x81\xf9\x9a\x16\xb8\xd8\x04\xd3',
    b'\x04'
    b'\x8e\x07\xe2\x19\xba\x58\x89\x16\xc5\xb0\x6a\xa3\x0a\x2f\x46\x4c'
    b'\x2f\x2a\xcf\xc1\x61\x0a\x3b\xe2\xfb\x24\x0b\x63\x53\x41\xf0\xdb'
    b'\x14\x8e\xa1\xd7\xd1\xe7\xe5\x4b\x95\x55\xb6\xc9\xac\x90\x62\x9c'
    b'\x18\xb6\x3b\xee\x5d\x7a\xa6\x94\x9e\xbb\xf4\x7b\x24\xfd\xe4\x0d'
)

# https://tools.ietf.org/html/rfc7027#appendix-A.1
bp256_data1 = (
    b'\x81\xdb\x1e\xe1\x00\x15\x0f\xf2\xea\x33\x8d\x70\x82\x71\xbe\x38'
    b'\x30\x0c\xb5\x42\x41\xd7\x99\x50\xf7\x7b\x06\x30\x39\x80\x4f\x1d',
    b'\x04'
    b'\x44\x10\x6e\x91\x3f\x92\xbc\x02\xa1\x70\x5d\x99\x53\xa8\x41\x4d'
    b'\xb9\x5e\x1a\xaa\x49\xe8\x1d\x9e\x85\xf9\x29\xa8\xe3\x10\x0b\xe5'
    b'\x8a\xb4\x84\x6f\x11\xca\xcc\xb7\x3c\xe4\x9c\xbd\xd1\x20\xf5\xa9'
    b'\x00\xa6\x9f\xd3\x2c\x27\x22\x23\xf7\x89\xef\x10\xeb\x08\x9b\xdc'
)

key[0] = PK_Crypto(0, data=bp256_data0)
key[1] = PK_Crypto(1, data=bp256_data1)
key[2] = PK_Crypto(2, data=bp256_data2)

PLAIN_TEXT0=b"In this test, we verify card generated result by libgcrypt."
PLAIN_TEXT1=b"Signature is non-deterministic (it uses nonce K internally)."
PLAIN_TEXT2=b"We don't use brainpoolp256r1 test vectors (it specifies K of ECDSA)."
PLAIN_TEXT3=b"NOTE: Our test is not for ECDSA implementation itself."

ENCRYPT_TEXT0 = sha256(b"encrypt me please").digest()
ENCRYPT_TEXT1 = sha256(b"encrypt me please, another").digest()
ENCRYPT_TEXT2 = sha256(b"encrypt me please, the other").digest()

test_vector = {
    'sign_0' : PLAIN_TEXT0,
    'sign_1' : PLAIN_TEXT1,
    'auth_0' : PLAIN_TEXT2,
    'auth_1' : PLAIN_TEXT3,
    'decrypt_0' : ENCRYPT_TEXT0,
    'decrypt_1' : ENCRYPT_TEXT1,
    'encrypt_0' : ENCRYPT_TEXT2,
}

brainpoolp256r1_pk = PK_Crypto()
brainpoolp256r1_pk.test_vector = test_vector
brainpoolp256r1_pk.key_list = key
brainpoolp256r1_pk.key_attr_list = [KEY_ATTRIBUTES_ECDSA_BRAINPOOLP256R1, KEY_ATTRIBUTES_ECDH_BRAINPOOLP256R1, KEY_ATTRIBUTES_ECDSA_BRAINPOOLP256R1]
brainpoolp256r1_pk.PK_Crypto = PK_Crypto
