# Comparison of features

### Feature overview

| Feature | Support by PE Studio | Support by CL version |
| ------- |:-------------------:|:---------------------:|
| Submit to Virus Total | Yes | Yes, if API key available |
| Check for TLS callbacks | Yes | Yes, all callbacks are listed |
| Show information from file header | Yes, highlights suspicious fields | Yes, highlights invalid date-time field only |
| Check imports against blacklisted libraries and functions. Cluster them according to their field | Yes | Yes |
| Prints exports of the PE file | Yes | Yes |
| Print summary of resources | Yes | Yes |
| Check for resources against list of known resources | Yes | Yes |
| Save selected resource to file to analyze it further | Yes | No |
| Show embedded certificates | Yes | No |
| Show relocations | Yes | Yes |
| Check for signatures in the file (e.g. packers, malware pattern). Note: database seems not to be up-to-date | Yes | Yes |
| Show blacklisted strings in the file by group | Yes | Yes |
| XML output of results | Yes | Yes |
| JSON output of results | No | Yes |
| Yara support for more rules | No | Yes |


### Indicators
In addition to PE Studio:
* Show summary of complete analysis of file
* Check for entropy in sections to quickly spot packers
* Check for imphashes
* List suspicious (= non-standard) section names because they can provide a hint to packers

All the indicators which should be supported by PE Studio and comparison to our version

| Indicators | Support by CL version | Note |
| ---------- |:---------------------:| ---- |
| The file is not an executable file | No | Our program won't parse the file correctly | 
| The MZ signature is missing | No | |
| The size (%i bytes) of the file is suspicious | No | |
| The size (%i bytes) of the optional-header is suspicious | Yes | |
| The size (%i bytes) of the file-header is suspicious | No | |
| The size (%i bytes) of the certificate is suspicious | No | |
| The content of the certificate is suspicious | No | |
| The file is Self-Extractable (SFX) | No | |
| The file references a certificate (offset: 0x%08X, size: %i bytes) | No | |
| The file is managed by .NET | No | |
| The file references (%s) debug symbol(s) | No | |
| The file references the Reflective DLL Injection technique | No | |
| The file is bound to (%i) library | No | |
| The file is Code-less | Yes | |
| The file exposes a TLS-callback (%s:%08X) | Yes | We can list all TLS callbacks |
| The entry-point is located in a section (name: %s) that is not executable | Yes | |
| The file checksum is invalid | No | |
| The entry-point is outside the file | Yes | |
| The certificate issuer (%s) has expired (%s) | Yes | |
| The certificate subject (%s) has expired (%s) | Yes | |
| The file does not contain a digital Certificate | Yes | |
| The file has no Manifest | Yes | |
| The Export table contains (%i) gap(s) | No | |
| The file implements Control Flow Guard (CFG) | Yes | |
| The file will be copied and run from to the system swap when started from the Network | No | |
| The file will be copied and run from to the system swap when started from a Removable Media | No | |
| The file runs in the Visual Basic Virtual Machine (VBVM) | No | |
| The file is a Device Driver | Yes | |
| The file is statically linked to the C Runtime Library | No | |
| The file opts for Data Execution Prevention (DEP) | Yes | |
| The file ignores Data Execution Prevention (DEP) | Yes | |
| The file opts for Address Space Layout Randomization (ASLR) | Yes | |
| The file ignores Address Space Layout Randomization (ASLR) | Yes | |
| The file ignores Structured Exception Handling (SEH) | Yes | |
| The file opts for cookies on the stack (GS) | Yes | |
| The file ignores cookies on the stack (GS) | Yes | |
| The file ignores Code Integrity | Yes | |
| The file is isolation aware but should not be isolated | No | |
| The file references Safe Structured Exception Handling (SafeSEH) | No | |
| The file registers (%i) Exception handlers | No | |
| The overlay is scored (%i/%i) by virustotal | No | |
| The MS-DOS Header has been found at (0x%08X) offset | No | |
| The value of the checksum is different than the checksum computed | No | |
| The file is scored (%i/%i) by virustotal | Yes | |
| The file has been compiled with Delphi | Yes | |
| The preferred AV engine (%s) detects the file as infected | No | |
| The preferred AV engine (%s) detects the file as clean | No | |
| The file references a debug symbols file (path:"%s") | Yes | Not sure if the debug file is found/parsed correctly |
| The debug file name extension is suspicous | Yes | Not sure if the debug file is found/parsed correctly |
| The GUID (%s) of the debug symbols is suspicious | No | |
| The path of the debug symbols is suspicious | No | |
| The age (%i) of the debug file is suspicious | No | |
| The value (0x%08X) of 'PointerToSymbolTable' is suspicious | No | |
| The value (%i) of 'NumberOfSymbols' is suspicious | No | |
| The value of 'SizeOfCode' is suspicious | No | |
| The value (0x%08X) of 'BaseOfCode' is suspicious | No | |
| The value (0x%08X) of 'BaseOfData' is suspicious | No | |
| The value of 'FileAlignment' is suspicious | No | |
| The value of 'SizeOfImage' is suspicious | Yes | |
| The size of initialized data reached the max (%i bytes) threshold | No | |
| The value of 'SizeOfHeaders' is suspicious | No | |
| The value (%i) of 'NumberOfRvaAndSizes' is suspicious | No | |
| The address of the entry-point is zero | Yes | |
| The shared section(s) reached the max (%i) threshold | Yes | |
| The file references a library (%s) that is missing | No | |
| The count of nameless sections reached the max (%i) threshold | No | |
| The file-ratio (%i) of the resources is suspicious | Yes | |
| The last section (name:%s) is executable | Yes | |
| The first section (name:%s) is writable | Yes | |
| The entry-point is outside the first section | No | We could add this feature|
| The entry-point is inside the first section | No | We could add this feature |
| The file size of the section (name:%s) reached the min (%i bytes) threshold | No | |
| The file signature is '%s' | No | |
| The file is resource-less | Yes | |
| The file references (%i) languages in the Resources | No | |
| The file contains (%i) custom resource item(s) | No | |
| The file contains (%i) built-in resources item(s) | No | |
| The file contains (%i) resource(s) in a blacklisted language (%s) | No | |
| The resource (type: %s, name: %s) is invalid | No | |
| The signature of the resource (%s:%s) is unknown | No | |
| The file references a resource (%s:%s) which is not supported anymore | No | |
| The manifest does not contain trust information | No | |
| The manifest identity name is "%s" | No | |
| The manifest description name (%s) is different than the file name (%s) | No | |
| The size of the resource (%s.%s) reached the min (%i bytes) threshold | No | |
| The size of the resource (%s.%s) is bigger than the max (%i bytes) threshold | No | |
| The section (name:%s) is blacklisted | Yes | Non-standard section names are result of the output |
| The count of executable sections reached the max (%i) threshold | Yes | |
| The file has no Executable section | Yes | |
| The count of blacklisted sections reached the max (%i) threshold | No | |
| The file references (%i) unknown resource(s) | No | |
| The file exports (%i) obsolete function(s) | No | |
| The file exports (%i) anonymous function(s) | No | |
| The file exports (%i) forwarded function(s) | No | |
| The file exports (%i) decorated function(s) | No | |
| The file exports (%i) duplicated function(s) | No | |
| The file exports blacklisted function(s) | No | |
| The dos-stub message ("%s") is unusual | No | |
| The dos-stub message is missing | No | |
| The file imports (%i) deprecated function(s) | No | |
| The file imports (%i) anonymous function(s) | No | |
| The file imports (%i) forwarded function(s) | No | |
| The file imports (%i) decorated function(s) | No | |
| The count (%i) of imports is suspicious | Yes | |
| The file imports blacklisted function(s) | Yes | |
| The file references (%i) whitelist strings | Yes | |
| The file references (%i) blacklisted library | Yes | |
| The count (%i) of antidebug functions reached the max (%i) threshold | Yes | |
| The count (%i) of undocumented functions reached the max (%i) threshold | No | |
| The count (%i) of ordinal functions reached the max (%i) threshold | No | |
| The count (%i) of deprecated functions reached the max (%i) threshold | No | |
| The dos-stub is missing | Yes | |
| The file iterates through running processes | No | We check if functions that can be used for it are imported |
| The file iterates through files on the disk | No | We check if functions that can be used for it are imported |
| The file imports (%i) undocumented function(s) | No | |
| The file subsystem is Unknown | No | |
| The %s directory is missing | No | |
| The %s directory is invalid | No | |
| The %s directory is outside the file | No | |
| The Offset (0x%08X) of the %s Directory is outside a section | No | |
| The Virtual Address (0x%08X) of the %s Directory is suspicious | No | |
| The count (%i) of empty directories reached the max (%i) threshold | No | |
| The time-stamp (Year:%i) of the compiler is suspicious | Yes | |
| The time-stamp (Year:%i) of the debugger is suspicious | Yes | |
| The file expects Administrative permission | No | |
| The file requests User Interface Privilege Isolation (UIPI) | No | |
| The file has no Cave | No | |
| The original file name is "%s" | No | |
| The file references (%i) blacklisted string(s) | No | |
| The strings reached the min (%i) threshold | No | |
| The file references an Object Indentifier (%s) | No | |
| The file references a MIME64 encoding string | No | |
| The file references a URL pattern (%s) | No | |
| The count (%i) of blacklisted strings reached the min (%i) threshold | No | |
| The file references a URL (%s) scored (%i/%i) by virustotal | No | |
| The file references a URL (%s) unknown by virustotal | No | |
| The file references function names mapped to other names | No | |
| The certificate references a URL (%s) | No | |
| The file imports (%i) library(s) with invalid name | No | |
| The file imports (%i) library(s) with suspicious name | No | |
| The count (%i) of libraries is suspicious | No | We could add this|
| The size (%i bytes) of the Version resource is bigger than the max (%i bytes) threshold | No | |
| The version '%s' is suspicious | No | |
| The version translation block internal name is misspelled | No | |
| The file supports OLE Self-Registration | No | |
| The file version has no Root | No | |
| The file contains another file (type: %s, location: %s, file-offset: 0x%08X) scored (%i/%i) by virustotal | No | |
| The file is target for % machine | No | We can parse the machine type but do not mention it as the indicators |
| The file references (%i) insulting string(s) | Yes | |
| The elevated functions reached the max (%i) threshold | No | |
| The registered exception handlers reached the max (%i) threshold | No | |
| The file contains another file (type: %s, location: %s, file-offset: 0x%08X) | No | |
| The size of the dos-header reached the min (%i bytes) threshold | No | |
| The size of the dos-header reached the max (%i bytes) threshold | No | |
| The file seems to be a fake Microsoft executable | No | |
| The size (%i bytes) of the dos-stub is suspicious | No | |
| The hash of the resource (%s.%s) is well-known | No | |
| The entry-point is located in the last section (name:%s) | Yes | |
| The count (%i) of sections is suspicious | No | We could add this |
| The file references the '%s' Windows builtin service | No | |
| The version information is missing | No | |
| The file is self-extractable with IEXPRESS | No | |
| The strings (type: %s) reached the max (%i) threshold | No | |
| The size of code (%i bytes) is bigger than the size (%i bytes) of code sections | Yes | |
| The file references Regular Expression (Regex) patterns | No | We check all strings |
| The section (name:%s) is not readable | No | |
| The file references (%i) Windows built-in privilege(s) | No | |
| The file signature (%s) is blacklisted | No | |
| The file signature (%s) of the overlay is blacklisted | No | |
| The file signature (%s) of the resource (%s.%s) is blacklisted | No | |
| The file contains self-modifying code | No | |
| The file extensions (%i) reached the max (%i) threshold | No | |
| The file references (%i) %s string(s) | No | |
| The file references (%i) functions of the '%s' API group | No | |
| The file references (%i) keyboard keys like a Keylogger | Yes | |
| The file references (%i) file extensions like a Ransomware (or a Wiper) | No | |
| The file references (%i) passwords like a Brute-forcer | Yes | |


All the features and functions of a PE file that should be checked. We can check all of them with the same logic as the original. However, not all of them seem to be supported by PEStudio (at least we couldn't find any library/function that is checked to perform the functionality of several of these messages)

| Feature/Functions | Support by CL version |
| ----------------- |:---------------------:|
| The file references the Smartcard API | Same as original |
| The file references a Virtual Machine (VM) | Same as original |
| The file references the Remote Desktop Session Host Server | Same as original |
| The file references the Protected Storage | Same as original |
| The file references the Active Directory (AD) | Same as original |
| The file references the Windows Native API | Same as original |
| The file references the Simple Network Management Protocol (SNMP) | Same as original |
| The file references the Security Descriptor Definition Language (SDDL) | Same as original |
| The file references the Cabinet (CAB) library | Same as original |
| The file references the eXtension for Financial Services (XFS) library | Same as original |
| The file references the Lightweight Directory Access Protocol (LDAP) | Same as original |
| The file modifies the Registry | Same as original |
| The file references the Security Account Manager (SAM) | Same as original |
| The file references the Clipboard | Same as original |
| The file references the installation of Hooks | Same as original |
| The file enumerates the list of running processes | Same as original |
| The file references the Service Control Manager (SCM) | Same as original |
| The file references the Reflective DLL Library injection technique | Same as original |
| The file references the Windows Indexing engine | Same as original |
| The file enumerates the list of loaded modules | Same as original |
| The file references the Desktop window | Same as original |
| The file references the Router Administration API | Same as original |
| The file references the Mail (MAPI) API | Same as original |
| The file references the Microsoft Identity Manager | Same as original |
| The file references the Windows Socket (winsock) API | Same as original |
| The file references the Internet Protocol Helper API | Same as original |
| The file references libraries at runtime | Same as original |
| The file spawns another process | Same as original |
| The file references the Microsoft Digest Access API | Same as original |
| The file references the Windows Cryptographic Primitives API | Same as original |
| The file references the Local Security Authority Server (LSASS) | Same as original |
| The file references the Local Security Authority (LSA) | Same as original |
| The file references the Internet Explorer Zone Manager | Same as original |
| The file references the Credential Manager User API | Same as original |
| The file references the Windows Setup API | Same as original |
| The file references the Windows Cryptographic API | Same as original |
| The file references the Windows Debug Helper API | Same as original |
| The file references the Windows IP Helper API | Same as original |
| The file references the Power Profile Helper API | Same as original |
| The file references the Multiple Provider Router (MPR) API | Same as original |
| The file references the File Transfer Protocol (FTP) API | Same as original |
| The file references users credentials | Same as original |
| The file references the resources of an executable | Same as original |
| The file enumerates files | Same as original |
| The file references the Backup API | Same as original |
| The file references the Global Atom Table | Same as original |
| The file creates or modifies file(s) | Same as original |
| The file references the Remote Access Service (RAS) API | Same as original |
| The file references the Performance Counters | Same as original |
| The file references the Event Log | Same as original |
| The file references the system Power | Same as original |
| The file references the HTML Help Control | Same as original |
| The file queries for Processes and Modules | Same as original |
| The file references Pipes | Same as original |
| The file references the Console | Same as original |
| The file references the Tasks Scheduler | Same as original |
| The file references the Windows Management Instrumentation (WMI) | Same as original |
| The file downloads bits from the Internet and save them to a file | Same as original |
| The file references the Windows default safe DLL search path | Same as original |
| The file references a Printer Driver | Same as original |
| The file references Dynamic Data Exchange (DDE) | Same as original |
| The file enumerates the list of registered windows | Same as original |
| The file references Function(s) callback executed when the program exits | Same as original |
| The file transfers control to a Debugger | Same as original |
| The file references the AutoIt scripting Engine | Same as original |
| The file references Microsoft the Setup Interface (MSI) | Same as original |
| The file references Microsoft Detour to trojanize other executable | Same as original |
| The file references the Domain Name System (DNS) API | Same as original |
| The file references temporary file(s) | Same as original |
| The file references the WLAN interface | Same as original |
| The file references the Environment variables | Same as original |
| The file references a Control Panel Application callback | Same as original |
| The file monitors Registry operations | Same as original |
| The file references the passwords of Internet Explorer | Same as original |
| The file references the DHCP Client Service | Same as original |
| The file references the NetBIOS or the DNS name of the local computer | Same as original |
| The file references the Windows Internet (WinINet) library | Same as original |
| The file references data on a Socket | Same as original |
| The file references the Internet Explorer (IE) server | Same as original |
| The file logs the Internet Explorer (IE) hits | Same as original |
| The file synthesizes Mouse motion and Buttons clicks | Same as original |
| The file references the protection of the Virtual Address space | Same as original |
| The file references the RPC Network Data Representation (NDR) Engine | Same as original |
| The file references the Windows Software Quality Metrics (SQM) | Same as original |
| The file references the Event Tracing for Windows (ETW) framework | Same as original |
| The file inserts itself in the chain of the Clipboard Listeners | Same as original |
| The file references the Open Database Connectivity (ODBC) installer | Same as original |
| The file references the Single-Instance Store (SIS) backup framework | Same as original |
| The file installs a Device or a Driver | Same as original |
| The file references the ODBC Driver Tracing mechanism | Same as original |
| The file references Bitlocker | Same as original |
| The file registers itself as a boot Driver | Same as original |
| The file walks up and records the stack information | Same as original |
| The file references the Windows Scripting Host (WSH) engine | Same as original |
| The file references the Console Based Script Host engine | Same as original |
| The file references the HTML Application Host engine | Same as original |
| The file references the VB Scripting Encoder/Decoder engine | Same as original |
| The file references the Java Scripting Encoder/Decoder engine | Same as original |
| The file references the Windows File Protection (WFP) | Same as original |
| The file simulates the Keyboard | Same as original |
| The file references the Multimedia Class Scheduler service (MMCSS) | Same as original |
| The file references the Group Policy (GP) | Same as original |
| The file references a communications device | Same as original |
| The file monitors a communications device | Same as original |
| The file references the local Running Object Table (ROT) | Same as original |
| The file references the Human Interface Devices (HID) Protocol | Same as original |
| The file references Simple Mail Transfer Protocol (SMTP) | Same as original |
| The file references the Internet Control Message Protocol (ICMP) | Same as original |
| The file fingerprints Antivirus or monitoring tools | Same as original |
| The file references the Windows network Capture Library | Same as original |
| The file references Microsoft Office | Same as original |
| The file enumerates Network resources | Same as original |
| The file references Alternate Data Stream (ADS) | Same as original |
| The file fingerprints Web browsers | Same as original |
| The file fingerprints Sandboxes | Same as original |
| The file fingerprints Email clients | Same as original |
| The file references the Firefox API | Same as original |
| The file references the Shim Engine | Same as original |
| The file references the Windows Address Book (WAB) | Same as original |
| The file references the Recycle Bin | Same as original |
| The file references the Volume Shadow Administration (vssadmin) tool | Same as original |
| The file references the Windows Scripting runtime | Same as original |
| The file references the gzip compression library | Same as original |
| The file enumerates the list of running threads | Same as original |
| The file enumerates the list of mounted folders | Same as original |
| The file installs an Exception Handler | Same as original |
| The file enumerates the existing Logon sessions | Same as original |
| The file enumerates the Display devices on the computer | Same as original |
| The file enumerates the Display monitors on the computer | Same as original |
| The file enumerates the cache of Internet Explorer | Same as original |
| The file references zLibDll, an open source ZLIB compression library | Same as original |
| The file references the Security Management API | Same as original |
| The file references the Authorization API | Same as original |
| The file references the Registry API | Same as original |
| The file references the Memory Management API | Same as original |
| The file references the Tool Help API | Same as original |
| The file references the Backup API | Same as original |
| The file references the Event Logging API | Same as original |
| The file references the Event Tracing API | Same as original |
| The file references the Error Handling API | Same as original |
| The file references the Directory Management API | Same as original |
| The file references the Debugging API | Same as original |
| The file references the Console API | Same as original |
| The file references the ImageHlp API | Same as original |
| The file references the COM API | Same as original |
| The file references the System Information API | Same as original |
| The file references the Package Query API | Same as original |
| The file references the Setup API | Same as original |
| The file references the Structured Storage API | Same as original |
| The file references the Dynamic Data Exchange Management Library (DDEML) API | Same as original |
| The file references the Clipboard API | Same as original |
| The file references the WinINet API | Same as original |
| The file references the Dynamic-Link Library API | Same as original |
| The file references the Process and Thread API | Same as original |
| The file references the WinHttp API | Same as original |
| The file references the (Zw) Native API | Same as original |
| The file references the (Rtl) Native API | Same as original |
| The file references the (Nt) Native API | Same as original |
| The file references the DHCP Server Management API | Same as original |
| The file references the Network Management API | Same as original |
| The file references the DNS API | Same as original |
| The file references the Mailslot API | Same as original |
| The file references the RPC API | Same as original |
| The file references the Structured Exception Handling (SEH) API | Same as original |
| The file references the Service API | Same as original |
| The file references the File Management API | Same as original |
| The file references the Video Capture API | Same as original |
| The file references the Cabinet API | Same as original |
| The file references the Single-Instance Store (SIS) Backup API | Same as original |
| The file references the Performance Counters API | Same as original |
| The file references the Atom API | Same as original |
| The file references the Device Management API | Same as original |
| The file references the Remote Access Service Custom Scripting API | Same as original |
| The file references the WinSNMP API | Same as original |
| The file references the Router Information API | Same as original |
| The file references the Network Data Representation (Ndr) API | Same as original |
| The file references the Power Management API | Same as original |
| The file references the Remote Desktop API | Same as original |
| The file references the WLAN API | Same as original |
| The file references the SNMP API | Same as original |
| The file references the WinDbgExt API | Same as original |
| The file references the DDE API | Same as original |
| The file references a Directory Notification watcher | Same as original |
| The file enumerates files on a FTP server | Same as original |
| The file references Meterpreter service | Same as original |


### Summary
What we support:
* Use customizable xml files (same as the original)
* Checking for (up to) 185 APIs and features which are referenced or implemented by the PE file
* Checking for blacklisted imports, resources and patterns (signature of packers)
* Extraction of all strings in the file and check against blacklisted strings
* XML and JSON output
* Interactive mode on command line
* Various command line options to specify the output
* Show TLS callbacks
* Show relocations
* Check file against yara rules
* Extract resources and save them in a file in order to allow further analysis (the analysis is not implemented)

Main missing features:
* Extracting resources and analyzing them further
* 131 of 176 Indicators are not implemented