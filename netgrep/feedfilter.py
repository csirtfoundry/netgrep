__all__ = ('FeedFilter')

import re
import csv
import socket
import sqlite3
import sys
from bulkwhois.cymru import BulkWhoisCymru
from async_dns import AsyncResolver
from publicsuffix import PublicSuffixList
import httplib2
import tempfile
import logging
import time

class NetObjectRepo:
    db = None

    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        # normally, we should store IPs as ints, but let's try to get away \
        # with it here
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
        row = self.db.execute("SELECT * from domains WHERE domain = ?", [domain]).fetchone()
        return row and row["cc"]

    def add_domain(self, domain, cc=""):
        domain_query = "SELECT id from domains WHERE domain = ?"
        if not list(self.db.execute(domain_query, [domain])):
            self.db.execute("INSERT INTO domains (domain, cc) VALUES (?, ?)", 
                            [domain, cc.upper()])
        return self.db.execute(domain_query, [domain]).fetchone()["id"]

    def add_domain_cc(self, domain, cc):
        self.add_domain(domain)
        self.db.execute("UPDATE domains SET cc=? WHERE domain=?", [cc.upper(), domain])

    def add_domain_ips(self, domain, ips):
        for ip in ips:
            ip_id = self.add_ip(ip)

            domain_id = self.add_domain(domain)

            self.db.execute("INSERT INTO domain_ips (domain_id, ip_id) VALUES (?, ?)", 
                        [domain_id, ip_id])

    def dump(self):
        for line in self.db.iterdump():
            logging.debug(line)

class FeedFilter:
    """
        Feedfilter takes in the arguments from the command line,
        processes them, and passes them out to an appropriate filter.
    """

    def __init__(self, **kwargs):
        """ args - passed in by optparse """
        self.delim = None
        self.cc_filters = []
        self.asn_filters = []
        self.format = None
        self.has_header = False
        self.infile = None
        self.outfile = None
        self.verbose = False
        self.quiet = False

        self.matchers = {}
        self.repo = NetObjectRepo()
       
        # regexs are intentionally broad - we'll run more tests later.

        self.matchers["ip"] = {
            "chk_func": self._is_valid_ip,
            "type": "ip",
        }
        self.matchers["uri"] = {
            "rex": "(?:(?:\w+)://)(?![^/@]+?@)?([^\/\s]+)",
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

        self.psl = PublicSuffixList(self._get_psl_file())

        self.parse_args(**kwargs)

    def _get_psl_file(self):
        url = 'http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1'
        headers = {'cache-control': 'max-age=%d' % (60*60*24)}
        http = httplib2.Http(tempfile.gettempdir())
        response, content = http.request(url, headers=headers)
        return content

    def parse_args(self, infile=sys.stdin, outfile=sys.stdout, verbose=False, 
                   verboser=False, quiet=False, has_header=False, 
                   format=None, filter=None, delim=None):
        
        def create_stdin_temp_file():
            f = tempfile.NamedTemporaryFile()
            for line in sys.stdin.read():
                f.write(line)
            # TODO: according to docs, a second open won't work on Win
            return open(f.name, "r")

        self.outfile = outfile
        self.verbose = verbose
        self.quiet = quiet
        self.has_header = has_header

        level = logging.WARN

        # quiet overrides everything else
        if verbose:
            level = logging.INFO
        if verboser:
            level = logging.DEBUG
        if quiet:
            level = logging.ERROR
 
        logging.basicConfig(level=level, format="%(message)s")
        
        if not infile or infile.name == "<stdin>":
            self.infile = create_stdin_temp_file()
        else:
            self.infile = infile

        if format and format != "delim" and delim:
            logging.warn("Warning: you've set both --format and --delim."+ 
                         " Using delimiter '%s' in --delim" % delim)
            self.delim = delim
        elif delim and str(delim):
            self.delim = delim
        elif format == "CSV":
            self.delim = ","
        elif format == "TSV":
            self.delim = "\t"
        else:
            self.delim = self._guess_delim()

        logging.info("I guess your delimiter as '%s'", self.delim)

        for filt in filter.split(','):
            for m in re.findall("^(?:AS)?(\d+)$", filt):
                self.asn_filters.append(m.upper())
            for m in re.findall("^[A-Za-z]+$", filt):
                self.cc_filters.append(m.upper())

        if len(self.asn_filters) == 0 and  len(self.cc_filters) == 0:
            #raise ValueError, "You need to specify at least one valid TLD or ASN filter. e.g. AS254,JP,AU"
            sys.exit("You need to specify --filter with at least one valid TLD or ASN filter. e.g. AS254,JP,AU")
        
        logging.info("Using filters: ")
        if self.asn_filters:
            logging.info("  ASN: %s" % (", ".join(self.asn_filters)))
        if self.cc_filters:
            logging.info("  Country codes: %s" % (", ".join(self.cc_filters)))

    def _guess_delim(self):
        sniffer = csv.Sniffer()
        self.infile.seek(0)
        sample = self.infile.read(2048)
        self.infile.seek(0)
        try:
            delim = sniffer.sniff(sample, "\t |,").delimiter
        except csv.Error:
            # out of ideas, only one field? Set to ','
            delim = ","
        return delim

    def domains_to_ips(self):
        ar = AsyncResolver([domain_data["domain"] for domain_data in self.repo.get_domain_data()])
        resolved = ar.resolve()

        for host, ips in resolved.items():
              if ips is None:
                  logging.debug("%s could not be resolved." % host)
              else:
                  self.repo.add_domain_ips(host, ips)
   
    def extract_matches(self):
        self.infile.seek(0)        
        for linenum, line in enumerate(self.infile.readlines()):
            # no need to parse a header line
            if self.has_header and linenum == 0:
                pass
            for (match_type, match) in self._get_line_matches(line, linenum):
                self.repo.add(match_type, match)

    def get_filtered_lines(self):
        self.infile.seek(0)

        for linenum, line in enumerate(self.infile.readlines()):
            if self.has_header and linenum == 0:
                yield(line)
            else:
                for match_type, match in self._get_line_matches(line, linenum, fetch_only_one=True):
                    if self.repo.belongs_to(datatype=match_type, data=match, asn_filters=self.asn_filters, cc_filters=self.cc_filters):
                        yield(line)
                        logging.debug("'%s' matches filter %s", match, match_type) 
                        break

    def output_matches(self):
        for line in self.get_filtered_lines():
            self.outfile.write(line)

    def _get_line_matches(self, line, line_num, fetch_only_one=False):
        try:
            match = False
            for cell in list(csv.reader([line], delimiter=self.delim))[0]:
                cell = cell.strip()
                for m_key, m_dict in self.matchers.items():
                    if "chk_func" in m_dict and "rex" in m_dict:
                        for m in re.findall(m_dict["rex"], cell):
                            if m_dict["chk_func"](m):
                                match = True
                                logging.debug("matched 'm' as")
                                yield((m_dict["type"], m))
                            if match and fetch_only_one:
                                break
                    elif "chk_func" in m_dict and m_dict["chk_func"](cell):
                        match = True
                        yield((m_dict["type"], cell))
                    elif "rex" in m_dict:
                        for m in re.findall(m_dict["rex"], cell):
                            match = True
                            yield((m_dict["type"], m))
                if match and fetch_only_one:
                    break
        except csv.Error as e:
            logging.warn("Error parsing line %d, skipping" % line_num)


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
        stime = time.time()
        logging.info("Extracting matches")
        self.extract_matches()
        logging.debug("Got matches " + str(time.time() - stime))
        if self.repo.get_domain_count() > 0:
            logging.info("Resolving " + str(self.repo.get_domain_count()) + " unique domains")
            self.domains_to_ips()
            logging.debug("Resolved IPs " + str(time.time() - stime))
            logging.info("Looking up ASNs")
        if self.repo.get_ip_count() > 0:
            self.add_asn_cc_info()
            logging.debug("Got asns " + str(time.time() - stime))
            logging.info("Getting domain CCs")
        self.add_domain_ccs()
        logging.debug("Added domain ccs " + str(time.time() - stime))
        self.repo.dump()

if __name__ == "__main__":
    feedfilter = FeedFilter({})
    if not feedfilter:
        exit
