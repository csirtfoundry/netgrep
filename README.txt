=======
netgrep
=======

Netgrep is a command line tool for filtering files based on country code and
Autonomous System Number (ASN). It will parse a text file, and then:

- match all domain names, URLs, email addresses and IP addresses
- resolve domains to IP addresses
- geo-locate IP addresses
- find domain name country based on TLD

Usage example:

input1.txt

abc.net.au,Australian Broadcasting Corporation
bbc.co.uk,British Broadcasting Corporation
203.2.218.214,Australian Broadcasting Corporation IP address

Command:

# match Australian IPs and domain names

$ cat input1.txt | netgrep AU
abc.net.au,Australian Broadcasting Corporation
203.2.218.214,Australian Broadcasting Corporation IP address

# match IPs resolving to Autonomous System 2818

$ cat input1.txt | netgrep AS2818
bbc.co.uk,British Broadcasting Corporation

# match both Australian IPs and domains and AS2818

$ cat input1.txt | netgrep AU,AS2818
abc.net.au,Australian Broadcasting Corporation
bbc.co.uk,British Broadcasting Corporation
203.2.218.214,Australian Broadcasting Corporation IP address

Further usage notes are available via --help

Installation
============

Prereqs:

pip install publicsuffix
pip install httplib2

adns for your platform. 
OS X: brew install adns

Then:

python setup.py install

Implementation notes
====================

Acknowledgements
