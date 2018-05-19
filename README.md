# pestudio-cli

Our goal is the implementation of a python-based command-line tool which can be used to check PE files for known malicious patterns. We therefore want to
* Submit the file to VirusTotal and present a summary of the result to the user
* Match the PE file against signatures of known malicious programs (the signatures are imported from PEStudio)
* Checking on blacklisted libraries/imports
* Checking for suspicious resources
