from lrw import *

def test_LRWMany():
    # test LRWMany with data generated from the python27 code
    from twofish import Twofish
    test_symmetric_key_header_1 = b'this is a test key with 32 bytes'
    test_lrwkey = b'meat  run  state'
    test_cleartext = b'this, is some data with 32 bytes'
    test_ciphertext = b'\xa23hGS\xf5\x89hx\xfdn"_\xb4\xfd\x10y\x89\xb3F\xc4\xa7\x90kv\xd9\xc4\xfb\x8akq\xa5'
    test_cipher = Twofish(test_symmetric_key_header_1)
    assert LRWMany(test_cipher.encrypt, test_lrwkey, 1, test_cleartext) == test_ciphertext 
    assert LRWMany(test_cipher.decrypt, test_lrwkey, 1, test_ciphertext) == test_cleartext

    # TODO add tests for other ciphers

def test_LRW():
    # assert that str2int function matches a known integer
    assert str2int(b'whatever') == 8604234240637691250
    # complex bytes check
    assert str2int(b'\x17F\xaf\xff>\xfc2\x8cQ\x8a\xe8\x88L\xd7.F') == 30939274327505541812725333202696613446
    assert int2str(8604234240637691250) == b'whatever'
    # complex bytes check
    assert int2str(30939274327505541812725333202696613446) == b'\x17F\xaf\xff>\xfc2\x8cQ\x8a\xe8\x88L\xd7.F'
    # assert a known computation from the python2.7 code
    # both values are over 16 bytes to test that facet
    assert xorstring16(b'something you want to do', b'something different that you want') == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1d\x06\x13F\x12\x13'
