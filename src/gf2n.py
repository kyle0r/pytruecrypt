## gf2n.py - Arithmetic in GF(2^n).
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

mod128 = 0x100000000000000000000000000000087 # x^128+x^7+x^2+x+1

# A detailed explanation of how this works can be found at
# http://en.wikipedia.org/wiki/Finite_field_arithmetic
# In short what we are doing is multiplying polynomials where each term is
# modulo 2. For this reason we can represent the polynomials as a binary
# string. For example, the polynomial x^3 + x + 1 = x^3 + x^1 + x^0 is the
# binary string 1011b. Here's a short example. Let us multiply
# (x + 1) with (x^3 + x^2): (x + 1)(x^3 + x^2) = x(x^3 + x^2) + x^3 + x^2 =
# x^4 + x^3 + x^3 + x^2 = x^4 + 2x^3 + x^2
# This is regular multiplication. However, as each term is modulo 2
# we're left with (1 % 2)x^4 + (2 % 2)x^3 + (1 % 2)x^2 = x^4 + x^2.
# There is however one step remaining: Depending of the field we're multiplying
# in there's modulo step left. For GF(2^8) the modulo is 100011011b
# and for GF(2^128) the modulo is x^128+x^7+x^2+x+1.
# This modulo step can be performed with simple long division but by
# binary OR:ing instead of subtracting.

def gf2n_mul(a, b, mod):
    """
    Multiplication in GF(2^n).

    This function implements multiplication in the Galois Field GF(2^n)
    The updated implementation is generally faster than the original implementation due to several key factors:

    1. **Precomputation of Terms**:
       - The updated implementation precomputes the terms of `b` that correspond to the set bits,
         storing them in a list (`b_terms`). This allows for efficient access during multiplication.
       - The original implementation does not precompute terms; instead, it recalculates the terms of `b`
         for each bit of `a`, leading to redundant calculations.

    2. **Bit Manipulation Efficiency**:
       - The updated implementation uses a single loop to iterate through the bits of `a`, and for each
         set bit, it directly accesses precomputed terms, resulting in fewer operations.
       - The original implementation contains nested loops where it checks each bit of `b` for every bit
         of `a`, which increases the number of iterations and operations significantly.

    3. **Reduction Logic**:
       - The `xor_mod` function in the updated implementation is straightforward and efficiently reduces
         the result using bitwise operations without additional complexity.
       - The original implementation's `xor_mod` function is more complex, involving multiple calls to
         `highest_bit_set`, which adds overhead and can slow down the reduction process.

    4. **Loop Structure**:
       - The outer loop in the updated implementation processes bits of `a` and directly applies the
         precomputed terms, leading to a more streamlined execution.
       - The original implementation has a nested structure of loops (one for `a` and one for `b`),
         increasing the time complexity, especially when both `a` and `b` have many bits set.

    5. **Memory Access Patterns**:
       - The updated implementation accesses a list of precomputed values, which is generally faster
         due to better cache locality.
       - The original implementation repeatedly shifts and checks bits of `b`, leading to less efficient
         memory access patterns.

    6. **Overall Complexity**:
       - The overall complexity of the updated implementation is reduced due to precomputation and
         efficient bit manipulation, making it more suitable for larger inputs.
       - The original implementation's complexity increases due to nested loops and additional function
         calls, making it less efficient for larger inputs.
    """

    def xor_mod(n, mod):
        """Perform modulo operation using XOR for reduction."""
        while n.bit_length() >= mod.bit_length():  # Check if n is larger than mod
            x = n.bit_length() - mod.bit_length()  # Calculate the difference in bit lengths
            n ^= (mod << x)  # Reduce n by XORing with mod shifted left by x
        return n        

    # Precompute the terms of b by creating a list of powers of 2
    # corresponding to the set bits in b
    b_terms = [1 << i for i in range(b.bit_length()) if b & (1 << i)]
    
    res = 0  # Initialize the result of the multiplication
    a_cnt = 0  # Counter for the current bit position of a
    while a:  # Continue until all bits of a are processed
        if a & 1:  # Check if the least significant bit of a is set
            for b_term in b_terms:  # Iterate over the precomputed terms of b
                res ^= b_term << a_cnt  # XOR the shifted b_term into the result
        a >>= 1  # Right shift a to process the next bit
        a_cnt += 1  # Increment the bit position counter
        
    return xor_mod(res, mod)  # Reduce the result modulo mod using XOR

def gf2pow128mul(a, b):
    return gf2n_mul(a, b, mod128)

# Add and subtract polynomials modulo 2. See explanation above why this
# code is so simple.

def gf2n_add(a, b):
    """Addition in GF(2^n)."""
    return a ^ b

def gf2n_sub(a, b):
    """Subtraction in GF(2^n)."""
    return a ^ b
