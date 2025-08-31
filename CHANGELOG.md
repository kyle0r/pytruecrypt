# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

This project uses version convention: `YEAR.WEEK.RELEASE`
Example: `date +'%G.%V.1'` where 1 is incremented per release within the given
week of the year.

## [2025.29.1] - 2025-07-16

### Removed

- References to the Python 2 `psyco` package
- Switched to mainstream packages for the following modules
  `rijndael.py`, `ripemd.py`, `twofish.py`, `whirlpool.py`

### Added

- `./requirements.txt` for the Python 3 venv
- `./tests` folder and created tests compatible with the `pytest` package - https://pytest.org/
- `./tests/conftest.py` to manage `pytest` config
- `CHANGELOG.md` per https://keepachangelog.com standard

### Changed

General

- Updated README.md
- Python 2to3 and related Python 3 changes
- Relevant in-module tests and assertions have been migrated to the ./tests hierarchy

./src/gf2n.py

- gf2n_mul() function has been optimised, see code docs

./src/keystrengthening.py

- switched to hashlib for sha1
- switched to pycryptodome RIPEMD160
- `hexdigest()` function updated to use python's native `hex()` function
- `HMAC()` code has been switched to the cpython implementation - see code docs
- PBKDF2 code has been refactored to be more performant and utilise some python native functions
- General update of the code docs

./src/lrw.py

- TODO consider replacing gf2n module with the `galois` package for performance
- Moved the `str2int()`, `int2str()`, `xorstring16()` functions outside of the `LRW()` function to make them testable. A consequence is these functions are now importable
- The `str2int()`, `int2str()`, `xorstring16()` functions have been refactored to be more performant and utilise some python native functions
- Refactored relevant `assert()` calls to raise `AssertionError()` otherwise the assertions could be skipped with `python3 -O`
- Added `LRW_blocksize` constant

./src/truecrypt.py

- Switched to pycryptodome for the Rijndael/AES cipher
- Added a simple Rijndael() class to wrap pycryptodome AES cipher
- Slight refactor of `CipherChain()` class which wasn't work as expected with Python 3
- Refactored relevant `assert()` calls to raise `AssertionError()` otherwise the assertions could be skipped with `python3 -O`
- Added support for specifying `/dev/null` or `nul` as the output file
- The file IO statements now use `with` blocks to gracefully manage file handles
- Refactored the `sys.exit()` calls to raise SystemExit() exceptions
- Factored a bunch of strings to use fixed strings

## [2008.01.01] - 2008-01-04

### Added

- Initial Python 2 standalone implementation by Björn Edström <be@bjrn.se>
  Written for his blog post entitled "TrueCrypt Explained". Archived: [here](https://web.archive.org/web/20241205141842/http://blog.bjrn.se/2008/01/truecrypt-explained.html).
  There is also an offline archive in the `misc/web-archive` folder.
