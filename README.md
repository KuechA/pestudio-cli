# pestudio-cli

### Goal
Our goal is the implementation of a python-based command-line tool which can be used to check PE files for known malicious patterns. We therefore
* Submit the file to VirusTotal and present a summary of the result to the user
* Match the PE file against signatures of known malicious programs (the signatures are imported from PEStudio). Currently, these are signatures of packers
* Check if the binary uses blacklisted libraries/imports
* Check for suspicious resources
* Examine the strings of the binary to find blacklisted values
* Show various information and highlight anomalies about the PE file like the PE header (time date stamp in the future), TLS callbacks or the relocations

### Dependencies
* prettytable python library: `pip3 install prettytable`
* LIEF to parse the PE file `pip3 install setuptools --upgrade; pip3 install lief`