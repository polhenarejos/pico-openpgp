from time import time
from struct import pack
from hashlib import sha1, sha512
from pk_signed_mpi_with_libgcrypt import PK_libgcrypt
from card_const import KEY_ATTRIBUTES_ECDH_NISTP521R1, KEY_ATTRIBUTES_ECDSA_NISTP521R1
lg_nistp521 = PK_libgcrypt(66, "NIST P-521")

class PK_Crypto(object):
    @staticmethod
    def pk_from_pk_info(pk_info):
        return pk_info[7:]

    @staticmethod
    def compute_digestinfo(msg):
        return sha512(msg).digest()

    @staticmethod
    def enc_data(enc_info):
        return b'\xa6\x81\x8c\x7f\x49\x81\x88\x86\x81\x85' + enc_info[1]

    @staticmethod
    def enc_check(enc_info, s):
        point = enc_info[0]
        # It's 04 || X || Y, extract X
        return point[1:67] == s


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
        m_len = 6 + 2 + 133
        ver = b'\x04'
        algo = b'\x12' if self.for_encryption else b'\x16'
        m = b'\x99' + pack('>H', m_len) + ver + self.timestamp + algo \
            + pack('>H', 1056+3) + self.q
        return sha1(m).digest()

    def build_privkey_template(self, is_yubikey):
        openpgp_keyno = self.keyno + 1
        if openpgp_keyno == 1:
            keyspec = b'\xb6'
        elif openpgp_keyno == 2:
            keyspec = b'\xb8'
        else:
            keyspec = b'\xa4'
        key_template = b'\x92\x42'
        exthdr = keyspec + b'\x00' + b'\x7f\x48' + b'\x02' + key_template
        suffix = b'\x5f\x48' + b'\x42'
        return b'\x4d' + b'\x4c' + exthdr + suffix + self.d

    def compute_signature(self, digestinfo):
        return lg_nistp521.call_pk_sign(self.d, digestinfo)

    def verify_signature(self, digestinfo, sig):
        return lg_nistp521.call_pk_verify(self.q, digestinfo, sig)

    def encrypt(self, plaintext):
        # Do ECDH
        return lg_nistp521.call_pk_encrypt(self.q, plaintext)

    def get_fpr(self):
        return self.fpr

    def get_timestamp(self):
        return self.timestamp

    def get_pk(self):
        return self.q

key = [ None, None, None ]

# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/186-3ecdsasiggencomponenttestvectors.zip

nistp521_data0 = (
    b'\x00\xf7\x49\xd3\x27\x04\xbc\x53\x3c\xa8\x2c\xef\x0a\xcf\x10\x3d'
    b'\x8f\x4f\xba\x67\xf0\x8d\x26\x78\xe5\x15\xed\x7d\xb8\x86\x26\x7f'
    b'\xfa\xf0\x2f\xab\x00\x80\xdc\xa2\x35\x9b\x72\xf5\x74\xcc\xc2\x9a'
    b'\x0f\x21\x8c\x86\x55\xc0\xcc\xcf\x9f\xee\x6c\x5e\x56\x7a\xa1\x4c'
    b'\xb9\x26',
    b'\x04'
    b'\x00\x61\x38\x7f\xd6\xb9\x59\x14\xe8\x85\xf9\x12\xed\xfb\xb5\xfb'
    b'\x27\x46\x55\x02\x7f\x21\x6c\x40\x91\xca\x83\xe1\x93\x36\x74\x0f'
    b'\xd8\x1a\xed\xfe\x04\x7f\x51\xb4\x2b\xdf\x68\x16\x11\x21\x01\x3e'
    b'\x0d\x55\xb1\x17\xa1\x4e\x43\x03\xf9\x26\xc8\xde\xbb\x77\xa7\xfd'
    b'\xaa\xd1'
    b'\x00\xe7\xd0\xc7\x5c\x38\x62\x6e\x89\x5c\xa2\x15\x26\xb9\xf9\xfd'
    b'\xf8\x4d\xce\xcb\x93\xf2\xb2\x33\x39\x05\x50\xd2\xb1\x46\x3b\x7e'
    b'\xe3\xf5\x8d\xf7\x34\x64\x35\xff\x04\x34\x19\x95\x83\xc9\x7c\x66'
    b'\x5a\x97\xf1\x2f\x70\x6f\x23\x57\xda\x4b\x40\x28\x8d\xef\x88\x8e'
    b'\x59\xe6'
)

nistp521_data2 = (
    b'\x01\xa4\xd2\x62\x3a\x7d\x59\xc5\x5f\x40\x83\x31\xba\x8d\x15\x23'
    b'\xb9\x4d\x6b\xf8\xac\x83\x37\x5c\xeb\x57\xa2\xb3\x95\xa5\xbc\xf9'
    b'\x77\xcf\xc1\x62\x34\xd4\xa9\x7d\x6f\x6e\xe2\x5a\x99\xaa\x5b\xff'
    b'\x15\xff\x53\x58\x91\xbc\xb7\xae\x84\x9a\x58\x3e\x01\xac\x49\xe0'
    b'\xe9\xb6',
    b'\x04'
    b'\x00\x4d\x5c\x8a\xfe\xe0\x38\x98\x4d\x2e\xa9\x66\x81\xec\x0d\xcc'
    b'\xb6\xb5\x2d\xfa\x4e\xe2\xe2\xa7\x7a\x23\xc8\xcf\x43\xef\x19\x90'
    b'\x5a\x34\xd6\xf5\xd8\xc5\xcf\x09\x81\xed\x80\x4d\x89\xd1\x75\xb1'
    b'\x7d\x1a\x63\x52\x2c\xeb\x1e\x78\x5c\x0f\x5a\x1d\x2f\x3d\x15\xe5'
    b'\x13\x52'
    b'\x00\x14\x36\x8b\x8e\x74\x68\x07\xb2\xb6\x8f\x36\x15\xcd\x78\xd7'
    b'\x61\xa4\x64\xdd\xd7\x91\x8f\xc8\xdf\x51\xd2\x25\x96\x2f\xdf\x1e'
    b'\x3d\xc2\x43\xe2\x65\x10\x0f\xf0\xec\x13\x33\x59\xe3\x32\xe4\x4d'
    b'\xd4\x9a\xfd\x8e\x5f\x38\xfe\x86\x13\x35\x73\x43\x2d\x33\xc0\x2f'
    b'\xa0\xa3'
)

# https://tools.ietf.org/html/rfc5903#section-8.1
nistp521_data1 = (
    b'\x00\x37\xad\xe9\x31\x9a\x89\xf4\xda\xbd\xb3\xef\x41\x1a\xac\xcc'
    b'\xa5\x12\x3c\x61\xac\xab\x57\xb5\x39\x3d\xce\x47\x60\x81\x72\xa0'
    b'\x95\xaa\x85\xa3\x0f\xe1\xc2\x95\x2c\x67\x71\xd9\x37\xba\x97\x77'
    b'\xf5\x95\x7b\x26\x39\xba\xb0\x72\x46\x2f\x68\xc2\x7a\x57\x38\x2d'
    b'\x4a\x52',
    b'\x04'
    b'\x00\x15\x41\x7e\x84\xdb\xf2\x8c\x0a\xd3\xc2\x78\x71\x33\x49\xdc'
    b'\x7d\xf1\x53\xc8\x97\xa1\x89\x1b\xd9\x8b\xab\x43\x57\xc9\xec\xbe'
    b'\xe1\xe3\xbf\x42\xe0\x0b\x8e\x38\x0a\xea\xe5\x7c\x2d\x10\x75\x64'
    b'\x94\x18\x85\x94\x2a\xf5\xa7\xf4\x60\x17\x23\xc4\x19\x5d\x17\x6c'
    b'\xed\x3e'
    b'\x01\x7c\xae\x20\xb6\x64\x1d\x2e\xeb\x69\x57\x86\xd8\xc9\x46\x14'
    b'\x62\x39\xd0\x99\xe1\x8e\x1d\x5a\x51\x4c\x73\x9d\x7c\xb4\xa1\x0a'
    b'\xd8\xa7\x88\x01\x5a\xc4\x05\xd7\x79\x9d\xc7\x5e\x7b\x7d\x5b\x6c'
    b'\xf2\x26\x1a\x6a\x7f\x15\x07\x43\x8b\xf0\x1b\xeb\x6c\xa3\x92\x6f'
    b'\x95\x82'
)

key[0] = PK_Crypto(0, data=nistp521_data0)
key[1] = PK_Crypto(1, data=nistp521_data1)
key[2] = PK_Crypto(2, data=nistp521_data2)

PLAIN_TEXT0=b"In this test, we verify card generated result by libgcrypt."
PLAIN_TEXT1=b"Signature is non-deterministic (it uses nonce K internally)."
PLAIN_TEXT2=b"We don't use NIST P-512 test vectors (it specifies K of ECDSA)."
PLAIN_TEXT3=b"NOTE: Our test is not for ECDSA implementation itself."

ENCRYPT_TEXT0 = sha512(b"!encrypt me please").digest()
ENCRYPT_TEXT1 = sha512(b"!!!encrypt me please, another").digest()
ENCRYPT_TEXT2 = sha512(b"!encrypt me please, the other").digest()

test_vector = {
    'sign_0' : PLAIN_TEXT0,
    'sign_1' : PLAIN_TEXT1,
    'auth_0' : PLAIN_TEXT2,
    'auth_1' : PLAIN_TEXT3,
    'decrypt_0' : ENCRYPT_TEXT0,
    'decrypt_1' : ENCRYPT_TEXT1,
    'encrypt_0' : ENCRYPT_TEXT2,
}

nistp521r1_pk = PK_Crypto()
nistp521r1_pk.test_vector = test_vector
nistp521r1_pk.key_list = key
nistp521r1_pk.key_attr_list = [KEY_ATTRIBUTES_ECDSA_NISTP521R1, KEY_ATTRIBUTES_ECDH_NISTP521R1, KEY_ATTRIBUTES_ECDSA_NISTP521R1]
nistp521r1_pk.PK_Crypto = PK_Crypto
