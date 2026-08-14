from cffi import FFI
import platform

ffi = FFI()

DEF_gcry_sexp="""
typedef unsigned long long size_t;
typedef void *gcry_sexp_t;
typedef unsigned int gcry_error_t;
gcry_error_t gcry_sexp_build (gcry_sexp_t *R_SEXP, size_t *ERROFF, const char *FORMAT, ...);
void gcry_sexp_release (gcry_sexp_t SEXP);
void gcry_sexp_dump (gcry_sexp_t SEXP);
gcry_sexp_t gcry_sexp_find_token (const gcry_sexp_t LIST, const char *TOKEN, size_t TOKLEN);
const char * gcry_sexp_nth_data (const gcry_sexp_t LIST, int NUMBER, size_t *DATALEN);
"""

DEF_gcry_pk_sign="""
typedef void *gcry_sexp_t;
typedef unsigned int gcry_error_t;
gcry_error_t gcry_pk_sign (gcry_sexp_t *R_SIG, gcry_sexp_t DATA, gcry_sexp_t SKEY);
"""

DEF_gcry_pk_verify="""
typedef void *gcry_sexp_t;
typedef unsigned int gcry_error_t;
gcry_error_t gcry_pk_verify (gcry_sexp_t SIG, gcry_sexp_t DATA, gcry_sexp_t PKEY);
"""

DEF_gcry_pk_encrypt="""
typedef void *gcry_sexp_t;
typedef unsigned int gcry_error_t;
gcry_error_t gcry_pk_encrypt (gcry_sexp_t *R_CIPH, gcry_sexp_t DATA, gcry_sexp_t PKEY);
"""

ffi.cdef(DEF_gcry_sexp)
ffi.cdef(DEF_gcry_pk_sign, override=True)
ffi.cdef(DEF_gcry_pk_verify, override=True)
ffi.cdef(DEF_gcry_pk_encrypt, override=True)

if (platform.system() == 'Darwin'):
    libgcrypt = ffi.dlopen("libgcrypt.20.dylib")
else:
    libgcrypt = ffi.dlopen("libgcrypt.so.20")


def fixup_scalar_cv25519(k):
    # Fixup is the responsibility for caller for Curve25519
    first_byte = int.to_bytes((k[0] & 0xf8), 1, 'big')
    last_byte = int.to_bytes(((k[-1] & 0x7f) | 0x40), 1, 'big')
    k_fixed_up = (first_byte + k[1:-1] + last_byte)
    return k_fixed_up[::-1]

FORMAT_KEY_CV25519_D=b"(private-key(ecc(curve Curve25519)(flags djb-tweak)(d%b)))"
FORMAT_KEY_ED25519_D=b"(private-key(ecc(curve Ed25519)(flags eddsa)(d%b)))"

def make_skey_by_secret(d,is_encr):
    sexp = ffi.new("void **")
    off = ffi.new("unsigned long long *")
    if is_encr:
        secret = ffi.new("char []", fixup_scalar_cv25519(d))
        r = libgcrypt.gcry_sexp_build(sexp, off, FORMAT_KEY_CV25519_D,
                                      ffi.cast("int", 32), secret)
    else:
        secret = ffi.new("char []", d)
        r = libgcrypt.gcry_sexp_build(sexp, off, FORMAT_KEY_ED25519_D,
                                      ffi.cast("int", 32), secret)
    if r != 0:
        raise ValueError("libgcrypt error", r)
    # libgcrypt.gcry_sexp_dump(sexp[0])
    return sexp[0]

FORMAT_DATA_ED25519=b"(data(flags eddsa)(hash-algo sha512)(value %b))"

def call_pk_sign(d, data):
    skey = make_skey_by_secret(d, False)

    data_in_c = ffi.new("char []", data)
    data_sexp = ffi.new("void **")
    off = ffi.new("unsigned long long *")
    r = libgcrypt.gcry_sexp_build(data_sexp, off, FORMAT_DATA_ED25519,
                                  ffi.cast("int", 32), data_in_c)
    if r != 0:
        raise ValueError("libgcrypt error", r)
    #
    sig_sexp = ffi.new("void **")
    libgcrypt.gcry_pk_sign(sig_sexp, data_sexp[0], skey)
    if r != 0:
        raise ValueError("libgcrypt error", r)
    #
    token_in_c = ffi.new("char []", b"r")
    r_sexp = libgcrypt.gcry_sexp_find_token(sig_sexp[0], token_in_c, 1)
    length = ffi.new("size_t *")
    sig_r = libgcrypt.gcry_sexp_nth_data(r_sexp, 1, length)
    token_in_c = ffi.new("char []", b"s")
    s_sexp = libgcrypt.gcry_sexp_find_token(sig_sexp[0], token_in_c, 1)
    sig_s = libgcrypt.gcry_sexp_nth_data(s_sexp, 1, length)
    return ffi.unpack(sig_r,32) + ffi.unpack(sig_s,32)

FORMAT_KEY_CV25519_Q=b"(private-key(ecc(curve Curve25519)(flags djb-tweak)(q%b)))"
FORMAT_KEY_ED25519_Q=b"(private-key(ecc(curve Ed25519)(flags eddsa)(q%b)))"

def make_skey_by_public(q,is_encr):
    public = ffi.new("char []", b'\x40' + q)
    sexp = ffi.new("void **")
    off = ffi.new("unsigned long long *")
    if is_encr:
        r = libgcrypt.gcry_sexp_build(sexp, off, FORMAT_KEY_CV25519_Q,
                                      ffi.cast("int", 33), public)
    else:
        r = libgcrypt.gcry_sexp_build(sexp, off, FORMAT_KEY_ED25519_Q,
                                      ffi.cast("int", 33), public)
    if r != 0:
        raise ValueError("libgcrypt error", r)
    # libgcrypt.gcry_sexp_dump(sexp[0])
    return sexp[0]

def call_pk_encrypt(q, ecdh_scalar):
    skey = make_skey_by_public(q, True)
    #
    shared_in_c = ffi.new("char []", fixup_scalar_cv25519(ecdh_scalar))
    data_sexp = ffi.new("void **")
    off = ffi.new("unsigned long long *")
    r = libgcrypt.gcry_sexp_build(data_sexp, off, b"%b",
                                  ffi.cast("int", 32), shared_in_c)
    if r != 0:
        raise ValueError("libgcrypt error", r)
    # libgcrypt.gcry_sexp_dump(data_sexp[0])

    ct_sexp = ffi.new("void **")
    r = libgcrypt.gcry_pk_encrypt(ct_sexp, data_sexp[0], skey)
    if r != 0:
        raise ValueError("libgcrypt error", r)
    # libgcrypt.gcry_sexp_dump(ct_sexp[0])
    token_in_c = ffi.new("char []", b"s")
    s_sexp = libgcrypt.gcry_sexp_find_token(ct_sexp[0], token_in_c, 1)
    length = ffi.new("size_t *")
    enc_s = libgcrypt.gcry_sexp_nth_data(s_sexp, 1, length)
    #
    token_in_c = ffi.new("char []", b"e")
    e_sexp = libgcrypt.gcry_sexp_find_token(ct_sexp[0], token_in_c, 1)
    enc_e = libgcrypt.gcry_sexp_nth_data(e_sexp, 1, length)
    #
    return (ffi.unpack(enc_s,33)[1:], ffi.unpack(enc_e,33)[1:])

FORMAT_SIG_ED25519=b"(sig-val(eddsa(r %b)(s %b)))"

def call_pk_verify(q, data, sig):
    skey = make_skey_by_public(q, False)

    data_in_c = ffi.new("char []", data)
    data_sexp = ffi.new("void **")
    off = ffi.new("unsigned long long *")
    r = libgcrypt.gcry_sexp_build(data_sexp, off, FORMAT_DATA_ED25519,
                                  ffi.cast("int", 32),  data_in_c)
    if r != 0:
        raise ValueError("libgcrypt error", r)

    sig_r_in_c = ffi.new("char []", sig[0:32])
    sig_s_in_c = ffi.new("char []", sig[32:])
    sig_sexp = ffi.new("void **")
    off = ffi.new("unsigned long long *")
    r = libgcrypt.gcry_sexp_build(sig_sexp, off, FORMAT_SIG_ED25519,
                                  ffi.cast("int", 32), sig_r_in_c,
                                  ffi.cast("int", 32), sig_s_in_c)
    if r != 0:
        raise ValueError("libgcrypt error", r)

    # libgcrypt.gcry_sexp_dump(sig_sexp[0])
    # libgcrypt.gcry_sexp_dump(data_sexp[0])
    r = libgcrypt.gcry_pk_verify(sig_sexp[0], data_sexp[0], skey)
    return r == 0
