__all__ = ('FeedFilter')

from delim_filter import DelimFilter
import argparse
import re
import csv
import socket
import sqlite3
import sys
from bulkwhois.cymru import BulkWhoisCymru
from async_dns import AsyncResolver
#import publicsuffix.publicsuffix as publicsuffix
from publicsuffix import PublicSuffixList
import httplib2
import tempfile

class NetObjectRepo:
    db = None

    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        # normally, we should store IPs as ints, but we can get away with it 
        # here
        self.db.execute("CREATE TABLE ips (id integer primary key, ip text unique, \
                    asn int, cc varchar)")
        self.db.execute("CREATE TABLE domains (id integer primary key, \
                    domain varchar unique, cc varchar)")
        self.db.execute("CREATE TABLE domain_ips (ip_id integer, \
                    domain_id integer)")

    def add(self, datatype="", data=""):
        if datatype == "ip":
            self.add_ip(data)
        elif datatype == "domain":
            self.add_domain(data)
        else:
            raise TypeError, "datatype must be of 'ip' or 'domain'"

    def belongs_to(self, datatype="", data="", asn_filters=None, cc_filters=None):
        if not data:
            raise TypeError, "Data cannot be empty"
        
        if datatype == "ip":
            return self.ip_belongs_to(data, asn_filters, cc_filters)
        elif datatype == "domain":
            return self.domain_belongs_to(data, asn_filters, cc_filters)
        else:
            raise TypeError, "datatype must be 'ip' or 'domain'"

    def ip_belongs_to(self, ip, asn_filters, cc_filters):
        query = "SELECT id FROM ips WHERE ip = ? AND ("
        params = [ip]
        if isinstance(asn_filters, list) and asn_filters:
            query = query + " asn in (" + ', '.join('?' for asn_filter in asn_filters) + ")"
            params.extend(asn_filters)
        if isinstance(cc_filters, list) and cc_filters:
            if len(params) > 1: # has ip + 1 or more asns
                query = query + " OR "
            query = query + " cc in (" + ', '.join('?' for cc_filter in cc_filters) + ")"
            params.extend(cc_filters)
        query = query + ")"
        rows = list(self.db.execute(query, params))
        return len(rows) >= 1

    def domain_belongs_to(self, domain, asn_filters, cc_filters):
        query = "SELECT d.id FROM domains d, ips i, domain_ips di WHERE d.domain = ? AND "
        params = [domain]
        query = query + " d.id = di.domain_id AND i.id = di.ip_id AND"
        
        query = query + " ("
        if isinstance(asn_filters, list) and asn_filters:
            query = query + " i.asn in (" + ', '.join('?' for asn_filter in asn_filters) + ")"
            params.extend(asn_filters)
        if isinstance(cc_filters, list) and cc_filters:
            if len(params) > 1: # has ip + 1 or more asns
                query = query + " OR "
            query = query + " i.cc in (" + ', '.join('?' for cc_filter in cc_filters) + ")"
            params.extend(cc_filters)
        
        query = query + ")"
        rows = list(self.db.execute(query, params))

        return len(rows) >= 1 or self.get_domain_tld(domain) in cc_filters

    def get_ip_data(self):
        for row in self.db.execute("SELECT * FROM ips"):
            yield(row)

    def get_ip_count(self):
        return self.db.execute("SELECT count(id) as ipcount from ips").fetchone()["ipcount"]

    def add_ip(self, ip):
        ip_query = "SELECT id from ips WHERE ip = ?"
        if not list(self.db.execute(ip_query, [ip])):
            self.db.execute("INSERT INTO ips (ip) VALUES (?)",
                            [ip])
        return self.db.execute(ip_query, [ip]).fetchone()["id"]

    def add_ip_asn_cc(self, ip, asn, cc):
        self.add_ip(ip)
        self.db.execute("UPDATE ips SET asn=?, cc=? WHERE ip=?", [asn, cc.upper(), ip])

    def get_domain_data(self):
        for row in self.db.execute("SELECT * FROM domains"):
            yield(row)

    def get_domain_count(self):
        return self.db.execute("SELECT count(id) as domcount from domains").fetchone()["domcount"]
    
    def get_domain_tld(self, domain):
        return self.db.execute("SELECT * from domains WHERE domain = ?", [domain]).fetchone()["cc"]

    def add_domain(self, domain, cc=""):
        domain_query = "SELECT id from domains WHERE domain = ?"
        if not list(self.db.execute(domain_query, [domain])):
            self.db.execute("INSERT INTO domains (domain, cc) VALUES (?, ?)", 
                            [domain, cc.upper()])
        return self.db.execute(domain_query, [domain]).fetchone()["id"]

    def add_domain_cc(self, domain, cc):
        self.add_domain(domain)
        self.db.execute("UPDATE domains SET cc=? WHERE domain=?", [cc.upper(), domain])

    def add_domain_ip(self, domain, ip):
        ip_id = self.add_ip(ip)
        domain_id = self.add_domain(domain)

        self.db.execute("INSERT INTO domain_ips (domain_id, ip_id) VALUES (?, ?)", 
                        [domain_id, ip_id])

    def dump(self):
        for line in self.db.iterdump():
            print line

class FeedFilter:
    """
        Feedfilter takes in the arguments from the command line,
        processes them, and passes them out to an appropriate filter.
    """

    delim = None
    cc_filters = []
    asn_filters = []
    format = None
    ignore_field = None
    has_header = False
    infile = None
    outfile = None
    verbose = False
    quiet = False

    matchers = {}
    repo = NetObjectRepo()

    def __init__(self, args):
        """ args - passed in by optparse """

        if type(args) != argparse.Namespace:
            return None
       
        # regexs are intentionally broad - we'll run more tests later.

        self.matchers["ip"] = {
            "chk_func": self._is_valid_ip,
            "type": "ip",
        }
        self.matchers["url"] = {
            "rex": "(?:(?:\w+)://)([^\/\s]+)",
            "type": "domain",
        }
        self.matchers["hostname"] = {
            "rex": "^([a-zA-Z0-9\-\.]+\.[0-9a-zA-Z\-\.]+)(?:\d+)?$",
            "chk_func": self._is_valid_domain,
            "type": "domain",
        }
        self.matchers["email"] = {
            "rex": ".*\@([\w\-\.]+)",
            "type": "domain",
        }

        # download the public suffix list or access cache in /tmp
        #self.psl = publicsuffix.public_suffix_list(
        #    http=httplib2.Http(tempfile.gettempdir()),
        #    headers={'cache-control': 'max-age=%d' % (60*60*24)}
        #)
        self.psl = PublicSuffixList(self._get_psl_file())

        self.parse_args(args)

    def _vprint(self, line):
        if self.verbose:
            sys.stderr.write("**" + str(line) + "\n")

    def _qprint(self, line):
        if not self.quiet:
            sys.stderr.write(line + "\n")

    def _get_psl_file(self):
        url = 'http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1'
        headers = {'cache-control': 'max-age=%d' % (60*60*24)}
        http = httplib2.Http(tempfile.gettempdir())
        response, content = http.request(url, headers=headers)
        return content

    def parse_args(self, args):
        
        def create_stdin_temp_file():
            f = tempfile.NamedTemporaryFile()
            for line in sys.stdin.read():
                f.write(line)
            # TODO: according to docs, a second open won't work on Win
            return open(f.name, "r")

        self.outfile = args.outfile
        self.verbose = args.verbose
        self.quiet = args.quiet
        self.has_header = args.has_header

        if not args.infile:
            self.infile = create_stdin_temp_file()
        else:
            self.infile = args.infile

        if args.format == "CSV":
            self.delim = ","
        elif args.format == "TSV":
            self.delim = "\t"
        elif args.format == "delim":
            self.delim = args.delim

        for filt in args.filter.split(','):
            for m in re.findall("^(?:AS)?(\d+)$", filt):
                self.asn_filters.append(m.upper())
            for m in re.findall("^[A-Za-z]+$", filt):
                self.cc_filters.append(m.upper())

        if len(self.asn_filters) == 0 and  len(self.cc_filters) == 0:
            #raise ValueError, "You need to specify at least one valid TLD or ASN filter. e.g. AS254,JP,AU"
            sys.exit("You need to specify --filter with at least one valid TLD or ASN filter. e.g. AS254,JP,AU")
        
        self._qprint("Using filters: ")
        if self.asn_filters:
            self._qprint("  ASN: %s" % (", ".join(self.asn_filters)))
        if self.cc_filters:
            self._qprint("  Country codes: %s" % (", ".join(self.cc_filters)))

    def domains_to_ips(self):
        #for domain_data in self.repo.get_domain_data():
        #    print domain_data
        ar = AsyncResolver([domain_data["domain"] for domain_data in self.repo.get_domain_data()])
        resolved = ar.resolve()

        for host, ip in resolved.items():
              if ip is None:
                  self._vprint("%s could not be resolved." % host)
              else:
                  self.repo.add_domain_ip(host, ip)
    
    def extract_matches(self):
        reader = csv.reader(self.infile, delimiter=self.delim)
        try:
            for linenum, line in enumerate(reader):
                # no need to parse a header line
                if self.has_header and linenum == 0:
                    pass
                for cell in line:
                    cell = cell.strip()
                    for m_key, m_dict in self.matchers.items():
                        if "chk_func" in m_dict and "rex" in m_dict:
                            for m in re.findall(m_dict["rex"], cell):
                                if m_dict["chk_func"](m):
                                    self.repo.add(m_dict["type"], m)
                        elif "chk_func" in m_dict and m_dict["chk_func"](cell):
                            self.repo.add(m_dict["type"], cell)
                        elif "rex" in m_dict:
                            for m in re.findall(m_dict["rex"], cell):
                                self.repo.add(m_dict["type"], m)
        except csv.Error as e:
            self._qprint("CSV parse error, skipping")

    def filter_print_matches(self):
        header_line = None
        self.infile.seek(0)
        
        for linenum, line in enumerate(self.infile.readlines()):
            print_line = False
            if self.has_header and linenum == 0:
                header_line = line
                continue
            #self._vprint("====\nOrig: " + line)
            try:
                for cell in list(csv.reader([line], delimiter=self.delim))[0]:
                    cell = cell.strip()
                    for m_key, m_dict in self.matchers.items():
                        if "chk_func" in m_dict and "rex" in m_dict:
                            for m in re.findall(m_dict["rex"], cell):
                                if m_dict["chk_func"](m):
                                    if self.repo.belongs_to(datatype=m_dict["type"], data=m, asn_filters=self.asn_filters, cc_filters=self.cc_filters):
                                        print_line = True
                                        break
                        elif "chk_func" in m_dict and m_dict["chk_func"](cell):
                            if self.repo.belongs_to(datatype=m_dict["type"], data=cell, asn_filters=self.asn_filters, cc_filters=self.cc_filters):
                                self._vprint("'%s' matched a filter" % (cell))
                                print_line = True
                        elif "rex" in m_dict:
                            for m in re.findall(m_dict["rex"], cell):
                                if self.repo.belongs_to(datatype=m_dict["type"], data=m, asn_filters=self.asn_filters, cc_filters=self.cc_filters):
                                    self._vprint("'%s' matched a filter" % (cell))
                                    print_line = True
                                    break

                        if print_line:
                            break
                    if print_line:
                        break
            except csv.Error as e:
                self._vprint("CSV parse error, skipping")

            if print_line == True:
                if header_line:
                    self.outfile.write(header_line)
                    header_line = None
                self.outfile.write(line)


    def _is_valid_domain(self, domain):
        if not str(domain):
            return None
        # don't want / need to resolve IPs
        elif self._is_valid_ip(domain):
            return None
        else:
            # using this PSL, known TLDs return at least one .
            return self._get_tld(domain).find(".") >= 0


    def _get_tld(self, domain):
        return self.psl.get_public_suffix(domain)

    def _is_valid_ip(self, ip):
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_pton(family, ip)
            except Exception as e:
                pass
            else:
                return True
        return False


    def add_asn_cc_info(self):
 
        def asn_lookup():
            bw = BulkWhoisCymru()
            ip_list = []
            for ip_data in self.repo.get_ip_data():
                ip_list.append(str(ip_data["ip"]))
            return bw.lookup_ips(ip_list)
        
        asn_info = asn_lookup()
        
        for ip_data in self.repo.get_ip_data():
            if ip_data["ip"] in asn_info:
                ip = ip_data["ip"]
                self.repo.add_ip_asn_cc(ip, asn=asn_info[ip]["asn"], cc=asn_info[ip]["cc"])

    def add_domain_ccs(self):
        for domain_data in self.repo.get_domain_data():
            tld = self._get_tld(domain_data["domain"])
            if tld:
                self.repo.add_domain_cc(domain_data["domain"], cc=(tld.split(".")[-1]))

    def process_file(self):
        import time
        stime = time.time()
        self._qprint("Extracting matches")
        self.extract_matches()
        print "Got matches " + str(time.time() - stime)
        if self.repo.get_domain_count() > 0:
            self._qprint("Resolving " + str(self.repo.get_domain_count()) + " unique domains")
            self.domains_to_ips()
            print "Resolved IPs " + str(time.time() - stime)
            self._qprint("Looking up ASNs")
        if self.repo.get_ip_count() > 0:
            self.add_asn_cc_info()
            print "Got asns " + str(time.time() - stime)
            self._qprint("Getting domain CCs")
        self.add_domain_ccs()
        print "Added domain ccs " + str(time.time() - stime)
        self.filter_print_matches()
        print "Filter printed output " + str(time.time() - stime)
        self.repo.dump()

if __name__ == "__main__":
    feedfilter = FeedFilter({})
    if not feedfilter:
        exit
