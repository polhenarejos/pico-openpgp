from time import time
from struct import pack
from hashlib import sha1, sha256
from pk_signed_mpi_with_libgcrypt import PK_libgcrypt
from card_const import KEY_ATTRIBUTES_ECDH_NISTP256R1, KEY_ATTRIBUTES_ECDSA_NISTP256R1

lg_nistp256 = PK_libgcrypt(32, "NIST P-256")

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
        return lg_nistp256.call_pk_sign(self.d, digestinfo)

    def verify_signature(self, digestinfo, sig):
        return lg_nistp256.call_pk_verify(self.q, digestinfo, sig)

    def encrypt(self, plaintext):
        # Do ECDH
        return lg_nistp256.call_pk_encrypt(self.q, plaintext)

    def get_fpr(self):
        return self.fpr

    def get_timestamp(self):
        return self.timestamp

    def get_pk(self):
        return self.q

key = [ None, None, None ]

# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/186-3ecdsasiggencomponenttestvectors.zip

nistp256_data0 = (
    b'\x51\x9b\x42\x3d\x71\x5f\x8b\x58\x1f\x4f\xa8\xee\x59\xf4\x77\x1a'
    b'\x5b\x44\xc8\x13\x0b\x4e\x3e\xac\xca\x54\xa5\x6d\xda\x72\xb4\x64',
    b'\x04'
    b'\x1c\xcb\xe9\x1c\x07\x5f\xc7\xf4\xf0\x33\xbf\xa2\x48\xdb\x8f\xcc'
    b'\xd3\x56\x5d\xe9\x4b\xbf\xb1\x2f\x3c\x59\xff\x46\xc2\x71\xbf\x83'
    b'\xce\x40\x14\xc6\x88\x11\xf9\xa2\x1a\x1f\xdb\x2c\x0e\x61\x13\xe0'
    b'\x6d\xb7\xca\x93\xb7\x40\x4e\x78\xdc\x7c\xcd\x5c\xa8\x9a\x4c\xa9'
)

nistp256_data2 = (
    b'\x0f\x56\xdb\x78\xca\x46\x0b\x05\x5c\x50\x00\x64\x82\x4b\xed\x99'
    b'\x9a\x25\xaa\xf4\x8e\xbb\x51\x9a\xc2\x01\x53\x7b\x85\x47\x98\x13',
    b'\x04'
    b'\xe2\x66\xdd\xfd\xc1\x26\x68\xdb\x30\xd4\xca\x3e\x8f\x77\x49\x43'
    b'\x2c\x41\x60\x44\xf2\xd2\xb8\xc1\x0b\xf3\xd4\x01\x2a\xef\xfa\x8a'
    b'\xbf\xa8\x64\x04\xa2\xe9\xff\xe6\x7d\x47\xc5\x87\xef\x7a\x97\xa7'
    b'\xf4\x56\xb8\x63\xb4\xd0\x2c\xfc\x69\x28\x97\x3a\xb5\xb1\xcb\x39'
)

# https://tools.ietf.org/html/rfc5903#section-8.1
nistp256_data1 = (
    b'\xc8\x8f\x01\xf5\x10\xd9\xac\x3f\x70\xa2\x92\xda\xa2\x31\x6d\xe5'
    b'\x44\xe9\xaa\xb8\xaf\xe8\x40\x49\xc6\x2a\x9c\x57\x86\x2d\x14\x33',
    b'\x04'
    b'\xda\xd0\xb6\x53\x94\x22\x1c\xf9\xb0\x51\xe1\xfe\xca\x57\x87\xd0'
    b'\x98\xdf\xe6\x37\xfc\x90\xb9\xef\x94\x5d\x0c\x37\x72\x58\x11\x80'
    b'\x52\x71\xa0\x46\x1c\xdb\x82\x52\xd6\x1f\x1c\x45\x6f\xa3\xe5\x9a'
    b'\xb1\xf4\x5b\x33\xac\xcf\x5f\x58\x38\x9e\x05\x77\xb8\x99\x0b\xb3'
)

key[0] = PK_Crypto(0, data=nistp256_data0)
key[1] = PK_Crypto(1, data=nistp256_data1)
key[2] = PK_Crypto(2, data=nistp256_data2)

PLAIN_TEXT0=b"In this test, we verify card generated result by libgcrypt."
PLAIN_TEXT1=b"Signature is non-deterministic (it uses nonce K internally)."
PLAIN_TEXT2=b"We don't use NIST P-256 test vectors (it specifies K of ECDSA)."
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

nistp256r1_pk = PK_Crypto()
nistp256r1_pk.test_vector = test_vector
nistp256r1_pk.key_list = key
nistp256r1_pk.key_attr_list = [KEY_ATTRIBUTES_ECDSA_NISTP256R1, KEY_ATTRIBUTES_ECDH_NISTP256R1, KEY_ATTRIBUTES_ECDSA_NISTP256R1]
nistp256r1_pk.PK_Crypto = PK_Crypto
