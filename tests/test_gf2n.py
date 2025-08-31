from gf2n import *

def test_things():

    assert gf2n_mul(0x53, 0xca, 0x11b) == 1
    assert gf2pow128mul(0xb9623d587488039f1486b2d8d9283453, 0xa06aea0265e84b8a) == 0xfead2ebe0998a3da7968b8c2f6dfcbd2
    assert gf2pow128mul(0x0696ce9a49b10a7c21f61cea2d114a22, 0x8258e63daab974bc) == 0x89a493638cea727c0bb06f5e9a0248c7
    assert gf2pow128mul(0xecf10f64ceff084cd9d9d1349c5d1918, 0xf48a39058af0cf2c) == 0x80490c2d2560fe266a5631670c6729c1
    assert gf2pow128mul(0x9c65a83501fae4d5672e54a3e0612727, 0x9d8bc634f82dfc78) == 0xd0c221b4819fdd94e7ac8b0edc0ab2cb
    assert gf2pow128mul(0xb8885a52910edae3eb16c268e5d3cbc7, 0x98878367a0f4f045) == 0xa6f1a7280f1a89436f80fdd5257ec579
    assert gf2pow128mul(0xd91376456609fac6f85748784c51b272, 0xf6d1fa7f5e2c73b9) == 0xbcbb318828da56ce0008616226d25e28
    assert gf2pow128mul(0x0865625a18a1aace15dba90dedd95d27, 0x395fcb20c3a2a1ff) == 0xa1c704fc6e913666c7bd92e3bc2cbca9
    assert gf2pow128mul(0x45ff1a2274ed22d43d31bb224f519fea, 0xd94a263495856bc5) == 0xd0f6ce03966ba1e1face79dfce89e830
    assert gf2pow128mul(0x0508aaf2fdeaedb36109e8f830ff2140, 0xc15154674dea15bf) == 0x67e0dbe4ddff54458fa67af764d467dd
    assert gf2pow128mul(0xaec8b76366f66dc8e3baaf95020fdfb5, 0xd1552daa9948b824) == 0x0a3c509baed65ac69ec36ae7ad03cc24
    assert gf2pow128mul(0x1c2ff5d21b5555781bbd22426912aa58, 0x5cdda0b2dafbbf2e) == 0xc9f85163d006bebfc548d010b6590cf2
    assert gf2pow128mul(0x1d4db0dfb7b12ea8d431680ac07ba73b, 0xa9913078a5c26c9b) == 0x6e71eaf1e7276f893a9e98a377182211
    assert gf2pow128mul(0xf7d946f08e94d545ce583b409322cdf6, 0x73c174b844435230) == 0xad9748630fd502fe9e46f36328d19e8d
    assert gf2pow128mul(0xdeada9ae22eff9bc3c1669f824c46823, 0x6bdd94753484db33) == 0xc40822f2f3984ed58b24bd207b515733
    assert gf2pow128mul(0x8146e084b094a0814577558be97f9be1, 0xb3fdd171a771c2ef) == 0xf0093a3df939fe1922c6a848abfdf474
    assert gf2pow128mul(0x7c468425a3bda18a842875150b58d753, 0x6358fcb8015c9733) == 0x369c44a03648219e2b91f50949efc6b4
    assert gf2pow128mul(0xe5f445041c8529d28afad3f8e6b76721, 0x06cefb145d7640d1) == 0x8c96b0834c896435fe8d4a70c17a8aff

    assert gf2n_mul(0x00, 0x00, 0x11b) == 0  # Multiplying zero by zero
    assert gf2n_mul(0x00, 0xca, 0x11b) == 0  # Multiplying zero by a non-zero
    assert gf2n_mul(0x53, 0x00, 0x11b) == 0  # Multiplying a non-zero by zero
    assert gf2n_mul(0x01, 0x01, 0x11b) == 0x01  # Multiplying one by one
    assert gf2n_mul(0x01, 0x53, 0x11b) == 0x53  # Multiplying one by a non-zero
    assert gf2n_mul(0x53, 0x01, 0x11b) == 0x53  # Multiplying a non-zero by one

    # === ADDITIONAL TESTS for gf2n_mul() ===

    # Multiplicative identity and zero
    assert gf2n_mul(1, 1, 0x11b) == 1           # 1 * 1 = 1
    assert gf2n_mul(123, 1, 0x11b) == 123       # x * 1 = x
    assert gf2n_mul(0, 55, 0x11b) == 0          # 0 * x = 0
    assert gf2n_mul(87, 0, 0x11b) == 0          # x * 0 = 0

    # Commutativity: a * b == b * a
    assert gf2n_mul(0x57, 0x83, 0x11b) == gf2n_mul(0x83, 0x57, 0x11b) == 0xc1

    # Known AES test vector: 0x57 * 0x13 mod 0x11b = 0xfe
    assert gf2n_mul(0x57, 0x13, 0x11b) == 0xfe

    # Known multiplication example: 0x02 * 0x87 mod 0x11b = 0x15
    assert gf2n_mul(0x02, 0x87, 0x11b) == 0x15

    # Associativity: a*(b*c) == (a*b)*c
    a, b, c = 0x53, 0xca, 0x13
    assert gf2n_mul(a, gf2n_mul(b, c, 0x11b), 0x11b) == gf2n_mul(gf2n_mul(a, b, 0x11b), c, 0x11b)

    # === GF(2^128) Algebraic Identities ===

    # Multiplication identity and zero
    x = 0x123456789abcdef0fedcba9876543210
    assert gf2pow128mul(x, 1) == x
    assert gf2pow128mul(1, x) == x
    assert gf2pow128mul(x, 0) == 0
    assert gf2pow128mul(0, x) == 0

    # Commutativity
    assert gf2pow128mul(0xabc, 0xdef) == gf2pow128mul(0xdef, 0xabc)

    # Associativity
    a, b, c = 0x1111, 0x2222, 0x3333
    assert gf2pow128mul(a, gf2pow128mul(b, c)) == gf2pow128mul(gf2pow128mul(a, b), c)

    # Additive identity and self-inverse
    y = 0xdeadbeef12345678
    assert gf2n_add(y, 0) == y
    assert gf2n_sub(y, 0) == y
    assert gf2n_add(y, y) == 0
    assert gf2n_sub(y, y) == 0

    # Maximum value test
    max128 = (1 << 128) - 1
    assert gf2pow128mul(max128, 1) == max128
    assert gf2pow128mul(max128, 0) == 0

    # XOR-based addition and subtraction equivalence
    a, b = 0xf0f0, 0x0f0f
    expected = a ^ b
    assert gf2n_add(a, b) == expected
    assert gf2n_sub(a, b) == expected

    # Fuzz tests for random 128-bit values
    import random
    random.seed(0)
    for _ in range(10):
        a = random.getrandbits(128)
        b = random.getrandbits(128)
        assert gf2pow128mul(a, b) == gf2pow128mul(b, a)  # Commutativity
        assert gf2n_add(a, b) == gf2n_sub(a, b)          # XOR-based add/sub are same