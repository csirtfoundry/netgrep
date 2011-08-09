=======
netgrep
=======

Netgrep is a command line tool for filtering files based on country code and
Autonomous System Number (ASN). It will parse a text file, and then:

- match all domain names, URLs, email addresses and IP addresses
- resolve domains to IP addresses
- geo-locate IP addresses
- find domain name countries based on TLD
- output each line matching at least one country code or ASN specified.

Basic usage
-----------

Input file: input1.txt

abc.net.au,Australian Broadcasting Corporation
bbc.co.uk,British Broadcasting Corporation
203.2.218.214,Australian Broadcasting Corporation IP address

Command:

# match Australian IPs and domain names

$ netgrep AU input1.txt
abc.net.au,Australian Broadcasting Corporation
203.2.218.214,Australian Broadcasting Corporation IP address

# match IPs resolving to Autonomous System 2818, owned by BBC

$ netgrep AS2818 input1.txt
bbc.co.uk,British Broadcasting Corporation

# match both Australian IPs / domains and AS2818

$ netgrep AU,AS2818 input1.txt
abc.net.au,Australian Broadcasting Corporation
bbc.co.uk,British Broadcasting Corporation
203.2.218.214,Australian Broadcasting Corporation IP address

Further usage notes are available via --help

Advanced usage
--------------

Multiple files

You can use wildcards or pass in multiple files:

$ netgrep AS444 logs/*.txt

Note that if you pass in multiple files, they may be in different formats.
Netgrep will try to guess what kind of delimiters are used in each.  However, 
you can only select one --delim, --format, or --has_headers for all files.

Standard input

netgrep supports piping from standard input like this:

$ cat input1.txt | netgrep BR

You can use netgrep as a quick little assertion tool. For example, does
akamai.com resolve to any boxes in Singapore?

$ echo "akamai.com" | netgrep SG
akamai.com  
# got output - assertion proven

$ echo "akamai.com" | netgrep FI
$ 
# no output - assertion failed

netgrep tries to guess how your file is delimited. This isn't foolproof, so
you can override it with --format and --delim, e.g.

$ netgrep -i input1.txt --format=CSV AU
...
$ netgrep -i input2.txt --format=delim --delim=\| AU
...

Installation
============

Prereqs:

pip install publicsuffix
pip install httplib2
pip install BulkWhois

adns for your platform. 
OS X: brew install adns
      pip install adns-python
Linux / aptitude: apt-get install python-adns

Then:

python setup.py install

Installation issues:
--------------------

When installing adns-python, you may receive:

adnsmodule.c:8:20: fatal error: Python.h: No such file or directory

sudo apt-get install python2.7-dev

Modify python2.7 for your version of Python, of course.

Implementation notes
====================


Limitations
-----------

* This initial release is focusing on functionality rather than performance for
matching. It's nowhere near as efficient as mighty grep: 
http://lists.freebsd.org/pipermail/freebsd-current/2010-August/019310.html?
* Pains have been taken to keep the memory footprint low and network calls
asynchronous / bulk where possible, though.
* netgrep only handles one record per line for now, so that means no multiline
XML parsing. If this might be useful, let me know 
[chris.horsley at csirtfoundry dot com].


Acknowledgements
================

Peteris Krumins (peter@catonmat.net) for his no-fuss interface to adns.
Made one very slight tweak to return multiple A records.

http://www.catonmat.net/blog/asynchronous-dns-resolution/

