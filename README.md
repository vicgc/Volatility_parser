Volatility_parser
=================

README for volatility_parser.bsh
--------------------------------
This script has been tested with Volatility 2.3.1 on Ubuntu.
Memorydump tested: 1GB memorydump from VM running Win7SP1x86, taken with "Live Ram Capturer"!

This simple bash-scriptet will try to parse out information from a memory dump and retrieve the most relevant information
for an anlyst, look below for what the scripts try to gather. The purpose is to automate this process.
This script will do absolutely nothing to analyse the output. This will however make it faster
to review the information gathered, because the analyst can search through text files instead of a big
memory dump.

Before you start to use this script, you have to set the full path for the following services:

* Python (default /usr/bin/python)
* Volatility (vol.py) (default /home/user/Volatility)
* Egrep (/bin/egrep)
* network (naft-gfe.py)
* sort (/usr/bin/sort)


Usage
-----------

./volatility_parser.bsh [casefolder] [memorydump] [profile]

eks:

./volatility_parser.bsh /home/xxx/working_case memdump.img Win7SP1x86

What does the script do?
------------------
The script will perform the following actions:
**All output will be stored in text files in relvant folders inside the case folder.
* Create a pcap of the IPv4 and ARP packets found inside the memory dump
* Dump all executeables in pslist**
* dump all .dll files**
* Hash (md5) exe and dll files**
* pslist** (shows all the running processes)
* psxview** (shows hidden processes)
* iehistory** (Contains wast information about activity from the user and internet history)
* modules**
* mutantscan**
* getsids** (Shows which user ran a specific program)
* dlllist**
* apihooks**
* thrdscan**
* malfind**
* idt**
* ssdt**
* hivescan**
* hivedump (dumps all the hives in registry to hive files.)

FAQ
-----

Why would some options fail?

If any of the above fails it is usually because that spesic command does not support
that particular profile. You could try another profile and see if that helps.
The most common ones to fail is under the network section or sockets. This is due to
support in volatility, not the script.

