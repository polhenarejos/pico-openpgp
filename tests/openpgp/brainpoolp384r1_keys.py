from time import time
from struct import pack
from hashlib import sha1, sha384
from pk_signed_mpi_with_libgcrypt import PK_libgcrypt
from card_const import KEY_ATTRIBUTES_ECDH_BRAINPOOLP384R1, KEY_ATTRIBUTES_ECDSA_BRAINPOOLP384R1

lg_bp384 = PK_libgcrypt(48, "brainpoolP384r1")

class PK_Crypto(object):
    @staticmethod
    def pk_from_pk_info(pk_info):
        return pk_info[5:]

    @staticmethod
    def compute_digestinfo(msg):
        return sha384(msg).digest()

    @staticmethod
    def enc_data(enc_info):
        return b'\xa6\x66\x7f\x49\x63\x86\x61' + enc_info[1]

    @staticmethod
    def enc_check(enc_info, s):
        point = enc_info[0]
        # It's 04 || X || Y, extract X
        return point[1:49] == s


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
        m_len = 6 + 2 + 97
        ver = b'\x04'
        algo = b'\x12' if self.for_encryption else b'\x16'
        m = b'\x99' + pack('>H', m_len) + ver + self.timestamp + algo \
            + pack('>H', 768+3) + self.q
        return sha1(m).digest()

    def build_privkey_template(self, is_yubikey):
        openpgp_keyno = self.keyno + 1
        if openpgp_keyno == 1:
            keyspec = b'\xb6'
        elif openpgp_keyno == 2:
            keyspec = b'\xb8'
        else:
            keyspec = b'\xa4'
        key_template = b'\x92\x30'
        exthdr = keyspec + b'\x00' + b'\x7f\x48' + b'\x02' + key_template
        suffix = b'\x5f\x48' + b'\x30'
        return b'\x4d' + b'\x3a' + exthdr + suffix + self.d

    def compute_signature(self, digestinfo):
        return lg_bp384.call_pk_sign(self.d, digestinfo)

    def verify_signature(self, digestinfo, sig):
        return lg_bp384.call_pk_verify(self.q, digestinfo, sig)

    def encrypt(self, plaintext):
        # Do ECDH
        return lg_bp384.call_pk_encrypt(self.q, plaintext)

    def get_fpr(self):
        return self.fpr

    def get_timestamp(self):
        return self.timestamp

    def get_pk(self):
        return self.q

key = [ None, None, None ]

# https://datatracker.ietf.org/doc/html/rfc6932#appendix-A.3

bp384_data0 = (
    b'\x01\x4e\xc0\x75\x5b\x78\x59\x4b\xa4\x7f\xb0\xa5\x6f\x61\x73\x04'
    b'\x5b\x43\x31\xe7\x4b\xa1\xa6\xf4\x73\x22\xe7\x0d\x79\xd8\x28\xd9'
    b'\x7e\x09\x58\x84\xca\x72\xb7\x3f\xda\xbd\x59\x10\xdf\x0f\xa7\x6a',
    b'\x04'
    b'\x45\xcb\x26\xe4\x38\x4d\xaf\x6f\xb7\x76\x88\x53\x07\xb9\xa3\x8b'
    b'\x7a\xd1\xb5\xc6\x92\xe0\xc3\x2f\x01\x25\x33\x27\x78\xf3\xb8\xd3'
    b'\xf5\x0c\xa3\x58\x09\x9b\x30\xde\xb5\xee\x69\xa9\x5c\x05\x8b\x4e'
    b'\x81\x73\xa1\xc5\x4a\xff\xa7\xe7\x81\xd0\xe1\xe1\xd1\x2c\x0d\xc2'
    b'\xb7\x4f\x4d\xf5\x8e\x4a\x4e\x3a\xf7\x02\x6c\x5d\x32\xdc\x53\x0a'
    b'\x2c\xd8\x9c\x85\x9b\xb4\xb4\xb7\x68\x49\x7f\x49\xab\x8c\xc8\x59'
)

bp384_data2 = (
    b'\x6b\x46\x1c\xb7\x9b\xd0\xea\x51\x9a\x87\xd6\x82\x88\x15\xd8\xce'
    b'\x7c\xd9\xb3\xca\xa0\xb5\xa8\x26\x2c\xbc\xd5\x50\xa0\x15\xc9\x00'
    b'\x95\xb9\x76\xf3\x52\x99\x57\x50\x6e\x12\x24\xa8\x61\x71\x1d\x54',
    b'\x04'
    b'\x01\xbf\x92\xa9\x2e\xe4\xbe\x8d\xed\x1a\x91\x11\x25\xc2\x09\xb0'
    b'\x3f\x99\xe3\x16\x1c\xfc\xc9\x86\xdc\x77\x11\x38\x3f\xc3\x0a\xf9'
    b'\xce\x28\xca\x33\x86\xd5\x9e\x2c\x8d\x72\xce\x1e\x7b\x46\x66\xe8'
    b'\x32\x89\xc4\xa3\xa4\xfe\xe0\x35\xe3\x9b\xdb\x88\x5d\x50\x9d\x22'
    b'\x4a\x14\x2f\xf9\xfb\xcc\x5c\xfe\x5c\xcb\xb3\x02\x68\xee\x47\x48'
    b'\x7e\xd8\x04\x48\x58\xd3\x1d\x84\x8f\x7a\x95\xc6\x35\xa3\x47\xac'
)

# https://tools.ietf.org/html/rfc7027#appendix-A.2
bp384_data1 = (
    b'\x1e\x20\xf5\xe0\x48\xa5\x88\x6f\x1f\x15\x7c\x74\xe9\x1b\xde\x2b'
    b'\x98\xc8\xb5\x2d\x58\xe5\x00\x3d\x57\x05\x3f\xc4\xb0\xbd\x65\xd6'
    b'\xf1\x5e\xb5\xd1\xee\x16\x10\xdf\x87\x07\x95\x14\x36\x27\xd0\x42',
    b'\x04'
    b'\x68\xb6\x65\xdd\x91\xc1\x95\x80\x06\x50\xcd\xd3\x63\xc6\x25\xf4'
    b'\xe7\x42\xe8\x13\x46\x67\xb7\x67\xb1\xb4\x76\x79\x35\x88\xf8\x85'
    b'\xab\x69\x8c\x85\x2d\x4a\x6e\x77\xa2\x52\xd6\x38\x0f\xca\xf0\x68'
    b'\x55\xbc\x91\xa3\x9c\x9e\xc0\x1d\xee\x36\x01\x7b\x7d\x67\x3a\x93'
    b'\x12\x36\xd2\xf1\xf5\xc8\x39\x42\xd0\x49\xe3\xfa\x20\x60\x74\x93'
    b'\xe0\xd0\x38\xff\x2f\xd3\x0c\x2a\xb6\x7d\x15\xc8\x5f\x7f\xaa\x59'
)

key[0] = PK_Crypto(0, data=bp384_data0)
key[1] = PK_Crypto(1, data=bp384_data1)
key[2] = PK_Crypto(2, data=bp384_data2)

PLAIN_TEXT0=b"In this test, we verify card generated result by libgcrypt."
PLAIN_TEXT1=b"Signature is non-deterministic (it uses nonce K internally)."
PLAIN_TEXT2=b"We don't use brainpoolp384r1 test vectors (it specifies K of ECDSA)."
PLAIN_TEXT3=b"NOTE: Our test is not for ECDSA implementation itself."

ENCRYPT_TEXT0 = sha384(b"encrypt me please").digest()
ENCRYPT_TEXT1 = sha384(b"encrypt me please, another").digest()
ENCRYPT_TEXT2 = sha384(b"encrypt me please, the other").digest()

test_vector = {
    'sign_0' : PLAIN_TEXT0,
    'sign_1' : PLAIN_TEXT1,
    'auth_0' : PLAIN_TEXT2,
    'auth_1' : PLAIN_TEXT3,
    'decrypt_0' : ENCRYPT_TEXT0,
    'decrypt_1' : ENCRYPT_TEXT1,
    'encrypt_0' : ENCRYPT_TEXT2,
}

brainpoolp384r1_pk = PK_Crypto()
brainpoolp384r1_pk.test_vector = test_vector
brainpoolp384r1_pk.key_list = key
brainpoolp384r1_pk.key_attr_list = [KEY_ATTRIBUTES_ECDSA_BRAINPOOLP384R1, KEY_ATTRIBUTES_ECDH_BRAINPOOLP384R1, KEY_ATTRIBUTES_ECDSA_BRAINPOOLP384R1]
brainpoolp384r1_pk.PK_Crypto = PK_Crypto
