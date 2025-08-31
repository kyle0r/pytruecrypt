import pytest
import truecrypt

tc_pw = 'password'.encode()

@pytest.fixture
def rijndael_sha1_container():
    with open('./tests/data/test-rijndael-sha1.tc', 'rb') as fileobj:
        yield fileobj

@pytest.fixture
def rijndael_twofish_serpent_sha1_container():
    with open('./tests/data/test-rijndael-twofish-serpent-sha1.tc', 'rb') as fileobj:
        yield fileobj

@pytest.fixture
def serpent_ripemd160_container():
    with open('./tests/data/test-serpent-ripemd160.tc', 'rb') as fileobj:
        yield fileobj

@pytest.fixture
def twofish_whirlpool_container():
    with open('./tests/data/test-twofish-whirlpool.tc', 'rb') as fileobj:
        yield fileobj

@pytest.fixture
def twofish_whirlpool_hidden_container():
    with open('./tests/data/test-twofish-whirlpool-hidden.tc', 'rb') as fileobj:
        yield fileobj

def test_rijndael_sha1_container(rijndael_sha1_container):
    tc = truecrypt.TrueCryptVolume(rijndael_sha1_container, tc_pw, truecrypt.Log)
    assert True is truecrypt.TCIsValidVolumeHeader(tc.decrypted_header)

def test_rijndael_twofish_serpent_sha1_container(rijndael_twofish_serpent_sha1_container):
    tc = truecrypt.TrueCryptVolume(rijndael_twofish_serpent_sha1_container, tc_pw, truecrypt.Log)
    assert True is truecrypt.TCIsValidVolumeHeader(tc.decrypted_header)

def test_serpent_ripemd160_container(serpent_ripemd160_container):
    tc = truecrypt.TrueCryptVolume(serpent_ripemd160_container, tc_pw, truecrypt.Log)
    assert True is truecrypt.TCIsValidVolumeHeader(tc.decrypted_header)

def test_twofish_whirlpool_container(twofish_whirlpool_container):
    tc = truecrypt.TrueCryptVolume(twofish_whirlpool_container, tc_pw, truecrypt.Log)
    assert True is truecrypt.TCIsValidVolumeHeader(tc.decrypted_header)

def test_twofish_whirlpool_hidden_container_outer(twofish_whirlpool_hidden_container):
    tc = truecrypt.TrueCryptVolume(twofish_whirlpool_hidden_container, 'outer'.encode(), truecrypt.Log)
    assert True is truecrypt.TCIsValidVolumeHeader(tc.decrypted_header)

def test_twofish_whirlpool_hidden_container_inner(twofish_whirlpool_hidden_container):
    tc = truecrypt.TrueCryptVolume(twofish_whirlpool_hidden_container, 'inner'.encode(), truecrypt.Log)
    assert True is truecrypt.TCIsValidVolumeHeader(tc.decrypted_header)

# TODO add a test case to test exception/unhappy paths including not able to seek when testing hidden containers