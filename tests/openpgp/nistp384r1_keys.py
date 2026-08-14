from time import time
from struct import pack
from hashlib import sha1, sha384
from pk_signed_mpi_with_libgcrypt import PK_libgcrypt
from card_const import KEY_ATTRIBUTES_ECDH_NISTP384R1, KEY_ATTRIBUTES_ECDSA_NISTP384R1

lg_nistp384 = PK_libgcrypt(48, "NIST P-384")

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
        return lg_nistp384.call_pk_sign(self.d, digestinfo)

    def verify_signature(self, digestinfo, sig):
        return lg_nistp384.call_pk_verify(self.q, digestinfo, sig)

    def encrypt(self, plaintext):
        # Do ECDH
        return lg_nistp384.call_pk_encrypt(self.q, plaintext)

    def get_fpr(self):
        return self.fpr

    def get_timestamp(self):
        return self.timestamp

    def get_pk(self):
        return self.q

key = [ None, None, None ]

# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/186-3ecdsasiggencomponenttestvectors.zip

nistp384_data0 = (
    b'\x20\x1b\x43\x2d\x8d\xf1\x43\x24\x18\x2d\x62\x61\xdb\x3e\x4b\x3f'
    b'\x46\xa8\x28\x44\x82\xd5\x2e\x37\x0d\xa4\x1e\x6c\xbd\xf4\x5e\xc2'
    b'\x95\x2f\x5d\xb7\xcc\xbc\xe3\xbc\x29\x44\x9f\x4f\xb0\x80\xac\x97',
    b'\x04'
    b'\xc2\xb4\x79\x44\xfb\x5d\xe3\x42\xd0\x32\x85\x88\x01\x77\xca\x5f'
    b'\x7d\x0f\x2f\xca\xd7\x67\x8c\xce\x42\x29\xd6\xe1\x93\x2f\xca\xc1'
    b'\x1b\xfc\x3c\x3e\x97\xd9\x42\xa3\xc5\x6b\xf3\x41\x23\x01\x3d\xbf'
    b'\x37\x25\x79\x06\xa8\x22\x38\x66\xed\xa0\x74\x3c\x51\x96\x16\xa7'
    b'\x6a\x75\x8a\xe5\x8a\xee\x81\xc5\xfd\x35\xfb\xf3\xa8\x55\xb7\x75'
    b'\x4a\x36\xd4\xa0\x67\x2d\xf9\x5d\x6c\x44\xa8\x1c\xf7\x62\x0c\x2d'
)

nistp384_data2 = (
    b'\x23\xd9\xf4\xea\x6d\x87\xb7\xd6\x16\x3d\x64\x25\x6e\x34\x49\x25'
    b'\x5d\xb1\x47\x86\x40\x1a\x51\xda\xa7\x84\x71\x61\xbf\x56\xd4\x94'
    b'\x32\x5a\xd2\xac\x8b\xa9\x28\x39\x4e\x01\x06\x1d\x88\x2c\x35\x28',
    b'\x04'
    b'\x5d\x42\xd6\x30\x1c\x54\xa4\x38\xf6\x59\x70\xba\xe2\xa0\x98\xcb'
    b'\xc5\x67\xe9\x88\x40\x00\x6e\x35\x62\x21\x96\x6c\x86\xd8\x2e\x8e'
    b'\xca\x51\x5b\xca\x85\x0e\xaa\x3c\xd4\x1f\x17\x5f\x03\xa0\xcb\xfd'
    b'\x4a\xef\x5a\x0c\xee\xce\x95\xd3\x82\xbd\x70\xab\x5c\xe1\xcb\x77'
    b'\x40\x8b\xae\x42\xb5\x1a\x08\x81\x6d\x5e\x5e\x1d\x3d\xa8\xc1\x8f'
    b'\xcc\x95\x56\x4a\x75\x27\x30\xb0\xaa\xbe\xa9\x83\xcc\xea\x4e\x2e'
)

# https://tools.ietf.org/html/rfc5903#section-8.1
nistp384_data1 = (
    b'\x09\x9f\x3c\x70\x34\xd4\xa2\xc6\x99\x88\x4d\x73\xa3\x75\xa6\x7f'
    b'\x76\x24\xef\x7c\x6b\x3c\x0f\x16\x06\x47\xb6\x74\x14\xdc\xe6\x55'
    b'\xe3\x5b\x53\x80\x41\xe6\x49\xee\x3f\xae\xf8\x96\x78\x3a\xb1\x94',
    b'\x04'
    b'\x66\x78\x42\xd7\xd1\x80\xac\x2c\xde\x6f\x74\xf3\x75\x51\xf5\x57'
    b'\x55\xc7\x64\x5c\x20\xef\x73\xe3\x16\x34\xfe\x72\xb4\xc5\x5e\xe6'
    b'\xde\x3a\xc8\x08\xac\xb4\xbd\xb4\xc8\x87\x32\xae\xe9\x5f\x41\xaa'
    b'\x94\x82\xed\x1f\xc0\xee\xb9\xca\xfc\x49\x84\x62\x5c\xcf\xc2\x3f'
    b'\x65\x03\x21\x49\xe0\xe1\x44\xad\xa0\x24\x18\x15\x35\xa0\xf3\x8e'
    b'\xeb\x9f\xcf\xf3\xc2\xc9\x47\xda\xe6\x9b\x4c\x63\x45\x73\xa8\x1c'
)

key[0] = PK_Crypto(0, data=nistp384_data0)
key[1] = PK_Crypto(1, data=nistp384_data1)
key[2] = PK_Crypto(2, data=nistp384_data2)

PLAIN_TEXT0=b"In this test, we verify card generated result by libgcrypt."
PLAIN_TEXT1=b"Signature is non-deterministic (it uses nonce K internally)."
PLAIN_TEXT2=b"We don't use NIST P-384 test vectors (it specifies K of ECDSA)."
PLAIN_TEXT3=b"NOTE: Our test is not for ECDSA implementation itself."

ENCRYPT_TEXT0 = sha384(b"!encrypt me please").digest()
ENCRYPT_TEXT1 = sha384(b"!!!encrypt me please, another").digest()
ENCRYPT_TEXT2 = sha384(b"!encrypt me please, the other").digest()

test_vector = {
    'sign_0' : PLAIN_TEXT0,
    'sign_1' : PLAIN_TEXT1,
    'auth_0' : PLAIN_TEXT2,
    'auth_1' : PLAIN_TEXT3,
    'decrypt_0' : ENCRYPT_TEXT0,
    'decrypt_1' : ENCRYPT_TEXT1,
    'encrypt_0' : ENCRYPT_TEXT2,
}


nistp384r1_pk = PK_Crypto()
nistp384r1_pk.test_vector = test_vector
nistp384r1_pk.key_list = key
nistp384r1_pk.key_attr_list = [KEY_ATTRIBUTES_ECDSA_NISTP384R1, KEY_ATTRIBUTES_ECDH_NISTP384R1, KEY_ATTRIBUTES_ECDSA_NISTP384R1]
nistp384r1_pk.PK_Crypto = PK_Crypto
