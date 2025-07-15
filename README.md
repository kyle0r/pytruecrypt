2025-July - Notes from Kyle

Back in January 2008, Björn published his research on TrueCrypt containers on his blog in a post entitled “TrueCrypt Explained”. Archived [here](https://web.archive.org/web/20241205141842/http://blog.bjrn.se/2008/01/truecrypt-explained.html). Björn's research provides lots of insights into TrueCrypt and cryptology, as well as a complete and functional code sample.

I saved an offline copy of the content in the `misc/web-archive` folder as a backup.

👍 It was great that Björn provided enough libraries for his code to run standalone, and even in 2025, the code still runs with Python 2.7 without any issues.

In 2025, while researching TrueCrypt's LRW mode, I came across Björn's research. As my objective was to decrypt some old LRW mode containers, I decided to update Björn's work to Python 3 to satisfy my curiosity and deepen my understanding. To document the original work and illustrate the changes I made, I included the original `src/*` files in the first commit of this repository.

## TODO
- Document `src/truecrypt.py` capabilities and features (incl. omissions/gaps).
- Use python `argparse` package for the cli interface
- Use the knowledge and code to update the `hashcat` project to support TrueCrypt LRW mode.  
  This would provide GPU accelerated cracking of the older LRW mode to compliment the existing XTS mode.

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
