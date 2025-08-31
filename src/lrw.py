## lrw.py - The LRW cryptographic mode.
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

import sys

# TODO consider replacing with galois package for performance
from gf2n import *

LRW_blocksize = 16

def str2int(str: bytes) -> int:
    # TODO assertions must observe sys.byteorder
    byteorder = 'big' # sys.byteorder
    return int.from_bytes(str, byteorder=byteorder)

def int2str(N: int) -> bytes:
    """
    Calculates the number of bytes required to represent the integer N in
    binary by obtaining its bit length with N.bit_length(), adding 7 to
    account for any remaining bits, and then performing integer division by
    8 to convert the bit count to bytes.
    Adding 7 before dividing by 8 ensures that any remaining bits of an
    integer N are accounted for, allowing for the correct allocation of
    bytes in the resulting bytes object.
    """
    num_bytes = (N.bit_length() + 7) // 8
    # TODO assertions must observe sys.byteorder
    byteorder = 'big' # sys.byteorder

    return N.to_bytes(num_bytes, byteorder=byteorder)

def xorstring16(a: bytes, b: bytes) -> bytes:
    """
    XORs the first 16 bytes of two byte strings.
    Optimised approach vs. the original
    """
    result = bytearray(16)  # Preallocate a bytearray for the result
    for i in range(16):
        result[i] = a[i] ^ b[i]  # Perform XOR for each byte
    return bytes(result)

# C_i = E_K1(P_i ^ (K2 x i)) ^ (K2 x i).
# Note that cipherfunc = E_K1, that is the key should already be set in E.
# lrwkey = K2.
def LRW(cipherfunc, lrwkey, i, block) -> bytes:
    """Perform an LRW operation."""
    if False is (LRW_blocksize == len(block)): raise AssertionError(f'block size must be {LRW_blocksize}')
    if False is (LRW_blocksize == len(lrwkey)): raise AssertionError(f'lrwkey size must be {LRW_blocksize}')
    K2 = str2int(lrwkey)
    # C_i = E_K1(P_i ^ K2i) ^ K2i
    K2i = int2str(gf2pow128mul(K2, i))
    # zero byte pad to LRW_blocksize bytes
    K2i = b'\x00' * (LRW_blocksize - len(K2i)) + K2i
    if False is (LRW_blocksize == len(K2i)): raise AssertionError(f'K2i size must be {LRW_blocksize}')
    return xorstring16(K2i, cipherfunc(xorstring16(K2i, block)))

def LRWMany(cipherfunc, lrwkey, i, blocks) -> bytes:
    num_blocks = len(blocks)
    if False is (num_blocks % LRW_blocksize == 0): raise AssertionError('the num_blocks does not divide equally by blocksize')
    data = b''
    for b in range(num_blocks // LRW_blocksize):
        data += LRW(cipherfunc, lrwkey, i + b, blocks[0:16])
        blocks = blocks[16:]
    return data
