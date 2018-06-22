# pestudio-cli

### Goal
Our goal is the implementation of a python-based command-line tool which can be used to check PE files for known malicious patterns. We therefore
* Submit the file to VirusTotal and present a summary of the result to the user
* Match the PE file against signatures of known malicious programs (the signatures are imported from PEStudio). Currently, these are signatures of packers
* Check if the binary uses blacklisted libraries/imports
* Check for suspicious resources
* Examine the strings of the binary to find blacklisted values
* Show various information and highlight anomalies about the PE file like the PE header (time date stamp in the future), TLS callbacks or the relocations
* Check the presence of more than 100 features in the PE file.
* On top, we check various suspicious values, among others a high entropy, known imphashes, anomalies of the entry-point address, sections, headers, data, ...
* Include support for yara rules by calling the yara-python library (if installed)

We support multiple output formats and make the output result highly configurable:
* Many options can be used to specify which analysis should be performed
* Output an xml file containing the desired information
* Output a JSON representation with the requested information
* A human-readable representation containing all the requested information at once
* An interactive mode can be used in order to show only selected information at a time

### Dependencies
* prettytable python library: `pip3 install prettytable`
* LIEF to parse the PE file `pip3 install setuptools --upgrade; pip3 install lief`
* In case files should be submitted to VirusTotal in order to retrieve their score, a [VirusTotal API key](https://www.virustotal.com/en/documentation/public-api/#getting-started) has to be stored in the file `VirusTotalApiKey` in the root of the directory.
* In order to use the functionality to check the file against [yara](https://virustotal.github.io/yara/) signatures, yara-python is required: `pip3 install yara-python`. Therefore, an installation of yara is required
