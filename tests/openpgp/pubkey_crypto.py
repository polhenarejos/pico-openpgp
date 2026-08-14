# from nistp256_keys import *
# from nistp384_keys import *
# from nistp521_keys import *
# from brainpoolp256r1_keys import *
# from brainpoolp384r1_keys import *
# from brainpoolp512r1_keys import *
import rsa_keys
import curve25519_keys

def get_PK_Crypto(card):
    if card.is_gnuk:
        return curve25519_keys.PK_Crypto
    else:
        return rsa_keys.PK_Crypto

def get_key(card):
    if card.is_gnuk:
        return curve25519_keys.key
    else:
        return rsa_keys.key

def get_test_vector(card):
    if card.is_gnuk:
        return curve25519_keys.test_vector
    else:
        return rsa_keys.test_vector
