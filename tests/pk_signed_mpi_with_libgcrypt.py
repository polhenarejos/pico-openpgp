from cffi import FFI

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

ffi = FFI()

ffi.cdef(DEF_gcry_sexp)
ffi.cdef(DEF_gcry_pk_sign, override=True)
ffi.cdef(DEF_gcry_pk_verify, override=True)
ffi.cdef(DEF_gcry_pk_encrypt, override=True)
libgcrypt = ffi.dlopen("libgcrypt.20.dylib")

FORMAT_DATA=b"(data(value %b))"
FORMAT_SIG=b"(sig-val(ecdsa(r %b)(s %b)))"

FORMAT_KEY_D_TMPL='(private-key(ecc(curve {0}:{1})(d%b)))'
FORMAT_KEY_Q_TMPL='(private-key(ecc(curve {0}:{1})(q%b)))'

class PK_libgcrypt(object):
    def __init__(self, dlen, cn):
        cn_len = len(cn)
        self.format_key_d = bytes(FORMAT_KEY_D_TMPL.format(cn_len,cn),"utf-8")
        self.format_key_q = bytes(FORMAT_KEY_Q_TMPL.format(cn_len,cn),"utf-8")
        self.dlen = dlen

    # Unfourtunately, in libgcrypt, D is signed
    def make_skey_by_secret(self, d):
        if d[0] >= 128:
            d = b'\x00' + d

        sexp = ffi.new("void **")
        off = ffi.new("unsigned long long *")
        secret = ffi.new("char []", d)
        r = libgcrypt.gcry_sexp_build(sexp, off, self.format_key_d,
                                      ffi.cast("int", len(d)), secret)
        if r != 0:
            raise ValueError("libgcrypt error", r)
        # libgcrypt.gcry_sexp_dump(sexp[0])
        return sexp[0]

    # Unfourtunately, in libgcrypt, DATA is signed
    def call_pk_sign(self, d, data):
        skey = self.make_skey_by_secret(d)

        if data[0] >= 128:
            data = b'\x00' + data

        data_in_c = ffi.new("char []", data)
        data_sexp = ffi.new("void **")
        off = ffi.new("unsigned long long *")
        r = libgcrypt.gcry_sexp_build(data_sexp, off, FORMAT_DATA,
                                      ffi.cast("int", len(data)), data_in_c)
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
        # libgcrypt.gcry_sexp_dump(sig_sexp[0])
        length = ffi.new("size_t *")
        sig_r = libgcrypt.gcry_sexp_nth_data(r_sexp, 1, length)
        len_sig_r = length[0]
        token_in_c = ffi.new("char []", b"s")
        s_sexp = libgcrypt.gcry_sexp_find_token(sig_sexp[0], token_in_c, 1)
        sig_s = libgcrypt.gcry_sexp_nth_data(s_sexp, 1, length)
        len_sig_s = length[0]
        #
        sig = bytes(self.dlen-len_sig_r)
        sig += ffi.unpack(sig_r,len_sig_r)
        sig += bytes(self.dlen-len_sig_s)
        sig += ffi.unpack(sig_s,len_sig_s)
        return sig

    # Unfourtunately, in libgcrypt, Q is signed, but luckily it always
    # starts with 0x04
    def make_skey_by_public(self, q):
        public = ffi.new("char []", q)
        sexp = ffi.new("void **")
        off = ffi.new("unsigned long long *")
        r = libgcrypt.gcry_sexp_build(sexp, off, self.format_key_q,
                                      ffi.cast("int", len(q)), public)
        if r != 0:
            raise ValueError("libgcrypt error", r)
        # libgcrypt.gcry_sexp_dump(sexp[0])
        return sexp[0]

    def call_pk_encrypt(self, q, ecdh_scalar):
        skey = self.make_skey_by_public(q)
        #
        if ecdh_scalar[0] >= 128:
            ecdh_scalar = b'\x00' + ecdh_scalar

        len_shared = len(ecdh_scalar)
        shared_in_c = ffi.new("char []", ecdh_scalar)
        data_sexp = ffi.new("void **")
        off = ffi.new("unsigned long long *")
        r = libgcrypt.gcry_sexp_build(data_sexp, off, b"%b",
                                      ffi.cast("int", len_shared), shared_in_c)
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
        len_s = length[0]
        #
        token_in_c = ffi.new("char []", b"e")
        e_sexp = libgcrypt.gcry_sexp_find_token(ct_sexp[0], token_in_c, 1)
        enc_e = libgcrypt.gcry_sexp_nth_data(e_sexp, 1, length)
        len_e = length[0]
        #
        return (ffi.unpack(enc_s,len_s), ffi.unpack(enc_e,len_e))

    # Unfourtunately, in libgcrypt, DATA, R and S is signed
    def call_pk_verify(self, q, data, sig):
        skey = self.make_skey_by_public(q)

        if data[0] >= 128:
            data = b'\x00' + data

        data_in_c = ffi.new("char []", data)
        data_sexp = ffi.new("void **")
        off = ffi.new("unsigned long long *")
        r = libgcrypt.gcry_sexp_build(data_sexp, off, FORMAT_DATA,
                                      ffi.cast("int", len(data)), data_in_c)
        if r != 0:
            raise ValueError("libgcrypt error", r)

        sig_r = sig[0:self.dlen]
        if sig_r[0] >= 128:
            sig_r = b'\x00' + sig_r

        sig_s = sig[self.dlen:]
        if sig_s[0] >= 128:
            sig_s = b'\x00' + sig_s

        sig_r_in_c = ffi.new("char []", sig_r)
        sig_s_in_c = ffi.new("char []", sig_s)

        sig_sexp = ffi.new("void **")
        off = ffi.new("unsigned long long *")
        r = libgcrypt.gcry_sexp_build(sig_sexp, off, FORMAT_SIG,
                                      ffi.cast("int", len(sig_r)), sig_r_in_c,
                                      ffi.cast("int", len(sig_s)), sig_s_in_c)
        if r != 0:
            raise ValueError("libgcrypt error", r)

        # libgcrypt.gcry_sexp_dump(sig_sexp[0])
        # libgcrypt.gcry_sexp_dump(data_sexp[0])
        r = libgcrypt.gcry_pk_verify(sig_sexp[0], data_sexp[0], skey)
        return r == 0
