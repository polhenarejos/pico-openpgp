from time import time
from struct import pack
from hashlib import sha1, sha256
from pk_25519_with_libgcrypt import fixup_scalar_cv25519, call_pk_sign, call_pk_encrypt, call_pk_verify
from card_const import KEY_ATTRIBUTES_CV25519, KEY_ATTRIBUTES_ED25519

class PK_Crypto(object):
    @staticmethod
    def pk_from_pk_info(pk_info):
        return b'\x40' + pk_info[5:]

    @staticmethod
    def compute_digestinfo(msg):
        return sha256(msg).digest()

    @staticmethod
    def enc_data(enc_info):
        return b'\xa6\x25\x7f\x49\x22\x86\x20' + enc_info[1]

    @staticmethod
    def enc_check(enc_info, s):
        return enc_info[0] == s


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
            if self.for_encryption:
                # Private part (in big endian), while DATA is native (little) endian
                d = data[0]
                self.d = fixup_scalar_cv25519(d)
            else:
                # Private part (in little (native) endian)
                self.d = data[0]
            self.q = data[1]
        self.fpr = self.calc_fpr()

    def calc_fpr(self):
        m_len = 6 + 2 + 33
        ver = b'\x04'
        algo = b'\x12' if self.for_encryption else b'\x16'
        m = b'\x99' + pack('>H', m_len) + ver + self.timestamp + algo \
            + pack('>H', 256+7) + b'\x40' + self.q
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
        return call_pk_sign(self.d, digestinfo)

    def verify_signature(self, digestinfo, sig):
        return call_pk_verify(self.q, digestinfo, sig)

    def encrypt(self, plaintext):
        # Do ECDH
        return call_pk_encrypt(self.q, plaintext)

    def get_fpr(self):
        return self.fpr

    def get_timestamp(self):
        return self.timestamp

    def get_pk(self):
        return b'\x40' + self.q

key = [ None, None, None ]

ed25519_data = (b'\x83\x3f\xe6\x24\x09\x23\x7b\x9d\x62\xec\x77\x58\x75\x20\x91\x1e'
                b'\x9a\x75\x9c\xec\x1d\x19\x75\x5b\x7d\xa9\x01\xb9\x6d\xca\x3d\x42',
                b'\xec\x17\x2b\x93\xad\x5e\x56\x3b\xf4\x93\x2c\x70\xe1\x24\x50\x34'
                b'\xc3\x54\x67\xef\x2e\xfd\x4d\x64\xeb\xf8\x19\x68\x34\x67\xe2\xbf')

cv25519_data = (b'\x77\x07\x6d\x0a\x73\x18\xa5\x7d\x3c\x16\xc1\x72\x51\xb2\x66\x45'
                b'\xdf\x4c\x2f\x87\xeb\xc0\x99\x2a\xb1\x77\xfb\xa5\x1d\xb9\x2c\x2a',
                b'\x85\x20\xf0\x09\x89\x30\xa7\x54\x74\x8b\x7d\xdc\xb4\x3e\xf7\x5a'
                b'\x0d\xbf\x3a\x0d\x26\x38\x1a\xf4\xeb\xa4\xa9\x8e\xaa\x9b\x4e\x6a')

key[0] = PK_Crypto(0, data=ed25519_data)
key[1] = PK_Crypto(1, data=cv25519_data)
key[2] = PK_Crypto(2, data=ed25519_data)

PLAIN_TEXT0=b"This is a test message."
PLAIN_TEXT1=b"cryptography is as easy as pie."

ENCRYPT_TEXT0 = sha256(b"encrypt me please").digest()
ENCRYPT_TEXT1 = sha256(b"encrypt me please, another").digest()
ENCRYPT_TEXT2 = sha256(b"encrypt me please, the other").digest()

test_vector = {
    'sign_0' : PLAIN_TEXT0,
    'sign_1' : PLAIN_TEXT1,
    'auth_0' : PLAIN_TEXT0,
    'auth_1' : PLAIN_TEXT1,
    'decrypt_0' : ENCRYPT_TEXT0,
    'decrypt_1' : ENCRYPT_TEXT1,
    'encrypt_0' : ENCRYPT_TEXT2,
}

curve25519_pk = PK_Crypto()
curve25519_pk.test_vector = test_vector
curve25519_pk.key_list = key
curve25519_pk.key_attr_list = [KEY_ATTRIBUTES_ED25519, KEY_ATTRIBUTES_CV25519, KEY_ATTRIBUTES_ED25519]
curve25519_pk.PK_Crypto = PK_Crypto
