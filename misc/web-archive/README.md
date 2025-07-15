The 7z archive contains an archive.org capture of the original 2008 blog content.
Why? Backup: for example, if archive.org goes offline.

The archive and its linked content and code should work offline and as a standalone webpage.

Most external JavaScripts and other code making external calls have been removed.

The web-archive was created using `wget` as follows:
```
wget --reject-regex ".*apis\.google\.com.*" --restrict-file-names=windows --recursive --mirror --convert-links --adjust-extension --page-requisites --no-clobber --domains web.archive.org  --level=2  --accept-regex ".*(blog\.bjrn\.se/2008/01/truecrypt-explained\.html|.*bjrn\.se/code/.*|.*\.(css|jpg|jpeg|png|gif|svg))" https://web.archive.org/web/20241205141842/http://blog.bjrn.se/2008/01/truecrypt-explained.html
```
Paste the command into a GenAI prompt to receive a detailed command breakdown.
