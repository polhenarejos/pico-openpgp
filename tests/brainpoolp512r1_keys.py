from time import time
from struct import pack
from hashlib import sha1, sha512
from pk_signed_mpi_with_libgcrypt import PK_libgcrypt
from card_const import KEY_ATTRIBUTES_ECDH_BRAINPOOLP512R1, KEY_ATTRIBUTES_ECDSA_BRAINPOOLP512R1

lg_bp512 = PK_libgcrypt(64, "brainpoolP512r1")

class PK_Crypto(object):
    @staticmethod
    def pk_from_pk_info(pk_info):
        return pk_info[7:]

    @staticmethod
    def compute_digestinfo(msg):
        return sha512(msg).digest()

    @staticmethod
    def enc_data(enc_info):
        return b'\xa6\x81\x88\x7f\x49\x81\x84\x86\x81\x81' + enc_info[1]

    @staticmethod
    def enc_check(enc_info, s):
        point = enc_info[0]
        # It's 04 || X || Y, extract X
        return point[1:65] == s


    def __init__(self, keyno=None, pk_info=None, data=None):
        if keyno == None:
            # Just for name space
            return

        self.keyno = keyno
        self.for_encryption = (self.keyno == 1)
        self.timestamp = pack('>I', int(time()))
        if pk_info:
            # Public part only (no private data) from card
            self.q = pk_info[7:]
        else:
            # Private part (in big endian)
            self.d = data[0]
            self.q = data[1]
        self.fpr = self.calc_fpr()

    def calc_fpr(self):
        m_len = 6 + 2 + 129
        ver = b'\x04'
        algo = b'\x12' if self.for_encryption else b'\x16'
        m = b'\x99' + pack('>H', m_len) + ver + self.timestamp + algo \
            + pack('>H', 1024+3) + self.q
        return sha1(m).digest()

    def build_privkey_template(self, is_yubikey):
        openpgp_keyno = self.keyno + 1
        if openpgp_keyno == 1:
            keyspec = b'\xb6'
        elif openpgp_keyno == 2:
            keyspec = b'\xb8'
        else:
            keyspec = b'\xa4'
        key_template = b'\x92\x40'
        exthdr = keyspec + b'\x00' + b'\x7f\x48' + b'\x02' + key_template
        suffix = b'\x5f\x48' + b'\x40'
        return b'\x4d' + b'\x4a' + exthdr + suffix + self.d

    def compute_signature(self, digestinfo):
        return lg_bp512.call_pk_sign(self.d, digestinfo)

    def verify_signature(self, digestinfo, sig):
        return lg_bp512.call_pk_verify(self.q, digestinfo, sig)

    def encrypt(self, plaintext):
        # Do ECDH
        return lg_bp512.call_pk_encrypt(self.q, plaintext)

    def get_fpr(self):
        return self.fpr

    def get_timestamp(self):
        return self.timestamp

    def get_pk(self):
        return self.q

key = [ None, None, None ]

# https://datatracker.ietf.org/doc/html/rfc6932#appendix-A.4

bp512_data0 = (
    b'\x63\x6b\x6b\xe0\x48\x2a\x6c\x1c\x41\xaa\x7a\xe7\xb2\x45\xe9\x83'
    b'\x39\x2d\xb9\x4c\xec\xea\x26\x60\xa3\x79\xcf\xe1\x59\x55\x9e\x35'
    b'\x75\x81\x82\x53\x91\x17\x5f\xc1\x95\xd2\x8b\xac\x0c\xf0\x3a\x78'
    b'\x41\xa3\x83\xb9\x5c\x26\x2b\x98\x37\x82\x87\x4c\xce\x6f\xe3\x33',
    b'\x04'
    b'\x05\x62\xe6\x8b\x9a\xf7\xcb\xfd\x55\x65\xc6\xb1\x68\x83\xb7\x77'
    b'\xff\x11\xc1\x99\x16\x1e\xcc\x42\x7a\x39\xd1\x7e\xc2\x16\x64\x99'
    b'\x38\x95\x71\xd6\xa9\x94\x97\x7c\x56\xad\x82\x52\x65\x8b\xa8\xa1'
    b'\xb7\x2a\xe4\x2f\x4f\xb7\x53\x21\x51\xaf\xc3\xef\x09\x71\xcc\xda'
    b'\xa7\xca\x2d\x81\x91\xe2\x17\x76\xa8\x98\x60\xaf\xbc\x1f\x58\x2f'
    b'\xaa\x30\x8d\x55\x1c\x1d\xc6\x13\x3a\xf9\xf9\xc3\xca\xd5\x99\x98'
    b'\xd7\x00\x79\x54\x81\x40\xb9\x0b\x1f\x31\x1a\xfb\x37\x8a\xa8\x1f'
    b'\x51\xb2\x75\xb2\xbe\x6b\x7d\xee\x97\x8e\xfc\x73\x43\xea\x64\x2e'
)

bp512_data2 = (
    b'\x0a\xf4\xe7\xf6\xd5\x2e\xdd\x52\x90\x7b\xb8\xdb\xab\x39\x92\xa0'
    b'\xbb\x69\x6e\xc1\x0d\xf1\x18\x92\xff\x20\x5b\x66\xd3\x81\xec\xe7'
    b'\x23\x14\xe6\xa6\xea\x07\x9c\xea\x06\x96\x1d\xba\x5a\xe6\x42\x2e'
    b'\xf2\xe9\xee\x80\x3a\x1f\x23\x6f\xb9\x6a\x17\x99\xb8\x6e\x5c\x8b',
    b'\x04'
    b'\x5a\x79\x54\xe3\x26\x63\xdf\xf1\x1a\xe2\x47\x12\xd8\x74\x19\xf2'
    b'\x6b\x70\x8a\xc2\xb9\x28\x77\xd6\xbf\xee\x2b\xfc\x43\x71\x4d\x89'
    b'\xbb\xdb\x6d\x24\xd8\x07\xbb\xd3\xae\xb7\xf0\xc3\x25\xf8\x62\xe8'
    b'\xba\xde\x4f\x74\x63\x6b\x97\xea\xac\xe7\x39\xe1\x17\x20\xd3\x23'
    b'\x96\xd1\x46\x21\xa9\x28\x3a\x1b\xed\x84\xde\x8d\xd6\x48\x36\xb2'
    b'\xc0\x75\x8b\x11\x44\x11\x79\xdc\x0c\x54\xc0\xd4\x9a\x47\xc0\x38'
    b'\x07\xd1\x71\xdd\x54\x4b\x72\xca\xae\xf7\xb7\xce\x01\xc7\x75\x3e'
    b'\x2c\xad\x1a\x86\x1e\xca\x55\xa7\x19\x54\xee\x1b\xa3\x5e\x04\xbe'
)

# https://tools.ietf.org/html/rfc7027#appendix-A.3
bp512_data1 = (
    b'\x16\x30\x2f\xf0\xdb\xbb\x5a\x8d\x73\x3d\xab\x71\x41\xc1\xb4\x5a'
    b'\xcb\xc8\x71\x59\x39\x67\x7f\x6a\x56\x85\x0a\x38\xbd\x87\xbd\x59'
    b'\xb0\x9e\x80\x27\x96\x09\xff\x33\x3e\xb9\xd4\xc0\x61\x23\x1f\xb2'
    b'\x6f\x92\xee\xb0\x49\x82\xa5\xf1\xd1\x76\x4c\xad\x57\x66\x54\x22',
    b'\x04'
    b'\x0a\x42\x05\x17\xe4\x06\xaa\xc0\xac\xdc\xe9\x0f\xcd\x71\x48\x77'
    b'\x18\xd3\xb9\x53\xef\xd7\xfb\xec\x5f\x7f\x27\xe2\x8c\x61\x49\x99'
    b'\x93\x97\xe9\x1e\x02\x9e\x06\x45\x7d\xb2\xd3\xe6\x40\x66\x8b\x39'
    b'\x2c\x2a\x7e\x73\x7a\x7f\x0b\xf0\x44\x36\xd1\x16\x40\xfd\x09\xfd'
    b'\x72\xe6\x88\x2e\x8d\xb2\x8a\xad\x36\x23\x7c\xd2\x5d\x58\x0d\xb2'
    b'\x37\x83\x96\x1c\x8d\xc5\x2d\xfa\x2e\xc1\x38\xad\x47\x2a\x0f\xce'
    b'\xf3\x88\x7c\xf6\x2b\x62\x3b\x2a\x87\xde\x5c\x58\x83\x01\xea\x3e'
    b'\x5f\xc2\x69\xb3\x73\xb6\x07\x24\xf5\xe8\x2a\x6a\xd1\x47\xfd\xe7'
)

key[0] = PK_Crypto(0, data=bp512_data0)
key[1] = PK_Crypto(1, data=bp512_data1)
key[2] = PK_Crypto(2, data=bp512_data2)

PLAIN_TEXT0=b"In this test, we verify card generated result by libgcrypt."
PLAIN_TEXT1=b"Signature is non-deterministic (it uses nonce K internally)."
PLAIN_TEXT2=b"We don't use brainpoolp512r1 test vectors (it specifies K of ECDSA)."
PLAIN_TEXT3=b"NOTE: Our test is not for ECDSA implementation itself."

ENCRYPT_TEXT0 = sha512(b"encrypt me please").digest()
ENCRYPT_TEXT1 = sha512(b"encrypt me please, another").digest()
ENCRYPT_TEXT2 = sha512(b"encrypt me please, the other").digest()

test_vector = {
    'sign_0' : PLAIN_TEXT0,
    'sign_1' : PLAIN_TEXT1,
    'auth_0' : PLAIN_TEXT2,
    'auth_1' : PLAIN_TEXT3,
    'decrypt_0' : ENCRYPT_TEXT0,
    'decrypt_1' : ENCRYPT_TEXT1,
    'encrypt_0' : ENCRYPT_TEXT2,
}

brainpoolp512r1_pk = PK_Crypto()
brainpoolp512r1_pk.test_vector = test_vector
brainpoolp512r1_pk.key_list = key
brainpoolp512r1_pk.key_attr_list = [KEY_ATTRIBUTES_ECDSA_BRAINPOOLP512R1, KEY_ATTRIBUTES_ECDH_BRAINPOOLP512R1, KEY_ATTRIBUTES_ECDSA_BRAINPOOLP512R1]
brainpoolp512r1_pk.PK_Crypto = PK_Crypto
