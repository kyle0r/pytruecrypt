2025-July - Notes from Kyle

Back in January 2008, Björn published his research on TrueCrypt containers on his blog in a post entitled “TrueCrypt Explained”. Archived [here](https://web.archive.org/web/20241205141842/http://blog.bjrn.se/2008/01/truecrypt-explained.html). Björn's research provides lots of insights into TrueCrypt and cryptology, as well as a complete and functional code sample.

I saved an offline copy of the content in the `misc/web-archive` folder as a backup.

👍 It was great that Björn provided enough libraries for his code to run standalone, and even in 2025, the code still runs with Python 2.7 without any issues.

In 2025, while researching TrueCrypt's LRW mode, I came across Björn's research. As my objective was to decrypt some old LRW mode containers, I decided to update Björn's work to Python 3 to satisfy my curiosity and deepen my understanding. To document the original work and illustrate the changes I made, I included the original `src/*` files in the first commit of this repository.

# [<img src="https://upload.wikimedia.org/wikipedia/commons/0/09/YouTube_full-color_icon_%282017%29.svg" height="25px">](https://youtu.be/2JPCltxUcrc) Intro video

I've hosted an [intro video on YouTube](https://youtu.be/VzStk_Rd6Bk), as its larger than the max supported attached file size.

[<img src="https://i.ytimg.com/vi/VzStk_Rd6Bk/maxresdefault.jpg" width="50%">](https://youtu.be/VzStk_Rd6Bk)

# INSTALL

To run the Python 3 code, try the following:
```
repo_url=https://github.com/kyle0r/pytruecrypt.git
# cd into the cloned repo dir
git clone "$repo_url" && cd $(basename "$repo_url" .git)

# setup python venv
python3 -m venv venv

# activate the venv
source venv/bin/activate

# install/upgrade dependencies
python3 -m pip install --upgrade pip
python3 -m pip install --use-pep517 -r requirements.txt

# Note: The following read command is bash specific - not POSIX compliant or portable.
# If you aren't using bash, paste the one-liner into a GenAI prompt and ask for a version for your preferred shell.
# store password in $REPLY var without echoing input
read -srp "enter password - no echo mode on: "; echo

# test the password against a test container
python3 ./src/truecrypt.py ./tests/data/test-rijndael-sha1.tc "$REPLY" output.log
```
💡 The test TrueCrypt containers all use the password: `password`

## JIT?
What about speeding things up with a Just-In-Time (JIT) compiler? The original Python 2 code utilised the `psyco` JIT package if it was available. I have included the following PyPy3 example as a replacement and comparison to the  `psyco` package. To run the Python 3 code with PyPy3 try the following:
```
# install pypy3 packages
sudo aptitude install pypy3 pypy3-dev

# as above clone the repo

# create the pyyp3 venv
pypy3 -m venv venv

# continue as above
```
💡 In my quick testing, I found that PyPy3 was slower than standard CPython for individual executions of `src/truecrypt.py` against a TrueCrypt container with an incorrect password.  
It is possible that PyPy3 could speed up the `truecrypt.TCReadSector` decryption loop, but I did not test this performance aspect, as my primary focus was on the TrueCrypt header.

---
# Tests
If you'd like to run the tests, then:
```
# from the repo root dir

# activate the venv
source venv/bin/activate

python3 -m pip install --upgrade pytest

pytest
```

---
# Historic Python 2 code

To run the historic Python 2 code: `git checkout pre-python3` tag from the repository and try the following:

```
# Note: The following read command is bash specific - not POSIX compliant or portable.
# If you aren't using bash, paste the one-liner into a GenAI prompt and ask for a version for your preferred shell.
# store password in $REPLY var without echoing input
read -srp "enter password - no echo mode on: "; echo

# test the password against a test container
# uses python -B to skip python byte code cache generation
python2.7 -B ./src/truecrypt.py ./tests/data/test-rijndael-sha1.tc "$REPLY" output.log
```

## TODO
- Document `src/truecrypt.py` capabilities and features (incl. omissions/gaps).
- Expand `src/truecrypt.py` test cases.
  - Consider asserting the output file of `truecrypt.TCReadSector` contains a known byte sequence.
  - Add test cases to cover exception/unhappy paths including not able to seek when testing hidden containers
- Use the python `argparse` package for the cli interface.
- Use obtained knowledge and code to extend the `hashcat` project to support TrueCrypt LRW mode.  
  This would provide GPU accelerated cracking of the older LRW mode to compliment the existing XTS mode.
- Create a simple Makefile to make installing, running tests, and other repetitive tasks easier.
  - Debian related: `apt -s install --no-install-recommends make`
  - Potential targets: install, test (covers linting), clean (remove venv and other cruft).
  - Clean target notes:
```
find . -depth -a \( -path './venv*' -o -path '*\.pytest_cache*' -o -path '*__pycache__*' \) -a -print -a -delete |less
```
