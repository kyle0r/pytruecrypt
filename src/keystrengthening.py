## keystrengthening.py - PBKDF2 algorithm.
## Copyright (c) 2008 Bjorn Edstrom <be@bjrn.se>
##
## Permission is hereby granted, free of charge, to any person
## obtaining a copy of this software and associated documentation
## files (the "Software"), to deal in the Software without
## restriction, including without limitation the rights to use,
## copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the
## Software is furnished to do so, subject to the following
## conditions:
##
## The above copyright notice and this permission notice shall be
## included in all copies or substantial portions of the Software.
##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
## EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
## OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
## NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
## HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
## WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
## FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
## OTHER DEALINGS IN THE SOFTWARE.


import struct
import math

from hashlib import sha1
from Crypto.Hash import RIPEMD160
import whirlpool

#
# Hash funcs.
#

def HASH_SHA1(data=None):
    return sha1(data) if data is not None else sha1()

def HASH_WHIRLPOOL(data=None):
    return whirlpool.new(data) if data is not None else whirlpool.new()

def HASH_RIPEMD160(data=None):
    return RIPEMD160.new(data) if data is not None else RIPEMD160.new()

def hexdigest(S):
    return S.hex()

#
# HMAC funcs.
# http://en.wikipedia.org/wiki/HMAC
#

trans_5C = bytes((x ^ 0x5C) for x in range(256))
trans_36 = bytes((x ^ 0x36) for x in range(256))

def HMAC(hash_func, hash_block_size, key, message):
    # Code taken from the cpython hmac.py class: https://t.ly/f6KZY
    # revision: 39cd9728a6770d8fe7937c57385cda5c2e25a223
    inner = hash_func()
    outer = hash_func()
    blocksize = getattr(inner, 'block_size', hash_block_size)
    if len(key) > blocksize:
        key = hash_func(key).digest()
    key = key + b'\x00' * (blocksize - len(key))
    inner.update(key.translate(trans_36))
    outer.update(key.translate(trans_5C))
    inner.update(message)
    outer.update(inner.digest())
    return outer.digest()

def HMAC_SHA1(key, message):
    return HMAC(HASH_SHA1, 64, key, message)
    
def HMAC_RIPEMD160(key, message):
    return HMAC(HASH_RIPEMD160, 64, key, message)
    
def HMAC_WHIRLPOOL(key, message):
    return HMAC(HASH_WHIRLPOOL, 64, key, message)

#
# PBKDF2.
# http://www.ietf.org/rfc/rfc2898.txt
#

def xor_string(a: bytearray, b: bytearray) -> bytearray:
    a_len = len(a)
    if a_len != len(b): raise AssertionError('''The length of the two strings being xor'ed must be the same.''')
    result = bytearray(a_len)  # Preallocate a bytearray for the result
    for i in range(a_len):
        result[i] = a[i] ^ b[i]  # Perform XOR for each byte
    return result

def PBKDF2(hmacfunc, password, salt, iterations, derivedlen):
    """Derive keys using the PBKDF2 key strengthening algorithm."""
    # Note that Python hashlib.pbkdf2_hmac() supports sha1 but does not support ripeme160 or whirlpool
    # Note that hashcat has some GPU code for pbkdf2 with sha1 but not ripeme160 or whirlpool
    hLen = len(hmacfunc(b'', b''))  # Digest size
    l = int(math.ceil(derivedlen / float(hLen)))  # Number of blocks needed
    r = derivedlen - (l - 1) * hLen  # Remaining bytes in the last block
    def F(P, S, c, i):
        U_prev = hmacfunc(P, S + struct.pack('>L', i))
        res = bytearray(U_prev)  # Pre-allocate a bytearray for the result
        for cc in range(2, c+1):
            U_c = bytearray(hmacfunc(P, U_prev))
            res = xor_string(res, U_c)
            U_prev = U_c
        return res
    # Pre-allocate a bytearray for the final derived key with the total size
    tmp = bytearray(l * hLen)
    i = 1
    offset = 0  # Offset to track where to write in tmp
    while True:
        block = F(password, salt, iterations, i)
        tmp[offset:offset + len(block)] = block  # Fill the pre-allocated bytearray
        offset += len(block)  # Update the offset
        if offset >= derivedlen:
            break
        i += 1

    return bytes(tmp[:derivedlen])  # Return the derived key as bytes
