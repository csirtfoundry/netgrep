=======
netgrep
=======

Netgrep is a command line tool which tells you which lines in a text file
contain network resources related to a particular country or Autonomous
Network (AS).

Given input, it will:

- locate domain names and IP addresses
- resolve domains to IP addresses
- geo-locate IP addresses to country codes and ASNs
- extract country codes from domain names 
- output each line matching at least one country code or ASN specified.

Example usage
-------------

# a simple log file

$ cat mylog.txt
abc.net.au,Australian Broadcasting Corporation
bbc.co.uk,British Broadcasting Corporation
203.2.218.214,Australian Broadcasting Corporation IP address

# match Australian IPs and domain names

$ netgrep AU mylog.txt
abc.net.au,Australian Broadcasting Corporation
203.2.218.214,Australian Broadcasting Corporation IP address

# match IPs resolving to Autonomous System 2818, owned by BBC

$ netgrep AS2818 mylog.txt
bbc.co.uk,British Broadcasting Corporation

# match both Australian IPs / domains and AS2818

$ netgrep AU,AS2818 mylog.txt
abc.net.au,Australian Broadcasting Corporation
bbc.co.uk,British Broadcasting Corporation
203.2.218.214,Australian Broadcasting Corporation IP address

Advanced usage
--------------

* Multiple files

You can use wildcards or pass in multiple files:

$ netgrep AS444 logs/firstlog.txt logs/secondlog.txt
...
$ netgrep AS444 logs/*.txt
...

Note the netgrep can't handle recursive subdirectories as yet.

* Piping standard input

Netgrep supports piping from standard input like this:

$ cat input1.txt | netgrep BR

You can use netgrep as a quick little assertion tool. For example, does
akamai.com resolve to any boxes in Singapore?

$ echo "akamai.com" | netgrep SG
akamai.com  
$
# got output - assertion proven

$ echo "akamai.com" | netgrep FI
$ 
# no output - assertion failed

Installation
============

You'll need:

adns
Python libraries:
  BulkWhois
  publicsuffix
  adns-python

Here's some OS-specific ways to install it:

* Linux install with apt-get:

sudo apt-get install python-pip git gcc python-dev python-adns
sudo pip install -e git://github.com/csirtfoundry/netgrep/netgrep.git#egg=netgrep

* OS X install:

brew install git
brew install adns
sudo easy_install pip
sudo pip install -e git://github.com/csirtfoundry/netgrep/netgrep.git#egg=netgrep

* Or, download and extract the tarball and then:

sudo python setup.py install

* Windows

Untested, and suspect it may not work. If you like to report how it did or
didn't work, please let me know.

Installation issues:
--------------------

When installing adns-python, you may receive:

adnsmodule.c:8:20: fatal error: Python.h: No such file or directory

sudo apt-get install python2.7-dev

Modify python2.7 for your version of Python, of course.

Implementation notes
====================

1. Netgrep makes one pass of the logs, extracting any candidate domain name and 
IP addresses it finds.

2. Domain names are checked to see if they resolve to a TLD present in the
Mozilla Public Suffix List. Anything not matching is ignored.

3. IP addresses are checked to ensure they're valid IPv4. IPv6 is currently
not supported, but there are plans to do this.

4. Domains are resolved to IP addresses asynchronously. This should be quite
fast for anything in the low hundreds, but may take a little time if you have
thousands.

5. All IPs gathered both directly from the log and via DNS resolution are
submitted via bulk query to Team Cymru's bulk whois service, retrieving
country code and ASN.

6. The file is scanned, the country code and ASN filters applied, and matching
lines are output.

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

