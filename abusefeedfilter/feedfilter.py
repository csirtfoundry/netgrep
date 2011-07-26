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
#import XMLFilter from xml_filter

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
        self.db.execute("CREATE TABLE text_refs (id integer unique, text varchar)")

    def add(self, datatype="", data=""):
        if datatype == "ip":
            self.add_ip(data)
        elif datatype == "domain":
            self.add_domain(data)
        else:
            raise TypeError, "datatype must be of 'ip' or 'domain'"

    def belongs_to(self, datatype="", data="", asn_filters=None, cc_filters=None):
        print "Belong to"
        if not data:
            raise TypeError, "Data cannot be empty"
        print data, asn_filters, cc_filters
        if datatype == "ip":
            return self.ip_belongs_to(data, asn_filters, cc_filters)
        elif datatype == "domain":
            return self.domain_belongs_to(data, asn_filters, cc_filters)
        else:
            raise TypeError, "datatype must be 'ip' or 'domain'"

    def ip_belongs_to(self, ip, asn_filters, cc_filters):
        query = "SELECT id FROM ips WHERE ip = ? AND ("
        params = [ip]
        if isinstance(asn_filters, list):
            query = query + " asn in (" + ', '.join('?' for asn_filter in asn_filters) + ")"
            params.extend(asn_filters)
        if isinstance(cc_filters, list):
            if params:
                query = query + " OR "
            query = query + " cc in (" + ', '.join('?' for cc_filter in cc_filters) + ")"
            params.extend(cc_filters)
        query = query + ")"
        print query
        print params
        rows = list(self.db.execute(query, params))
        print rows
        print len(rows)
        return len(rows) >= 1

    def get_ip_data(self):
        for row in self.db.execute("SELECT * FROM ips"):
            yield(row)

    def add_ip(self, ip):
        ip_query = "SELECT id from ips WHERE ip = ?"
        if not list(self.db.execute(ip_query, [ip])):
            self.db.execute("INSERT INTO ips (ip) VALUES (?)",
                            [ip])
        return self.db.execute(ip_query, [ip]).fetchone()["id"]

    def add_ip_asn_cc(self, ip, asn, cc):
        self.add_ip(ip)
        self.db.execute("UPDATE ips SET asn=?, cc=? where ip=?", [asn, cc, ip])

    def get_domain_data(self):
        for row in self.db.execute("SELECT * from domains"):
            yield(row)

    def add_domain(self, domain, cc=""):
        domain_query = "SELECT id from domains WHERE domain = ?"
        if not list(self.db.execute(domain_query, [domain])):
            self.db.execute("INSERT INTO domains (domain, cc) VALUES (?, ?)", 
                            [domain, cc])
        return self.db.execute(domain_query, [domain]).fetchone()["id"]

    def add_domain_ip(self, domain, ip):
        ip_id = self.add_ip(ip)
        domain_id = self.add_domain(domain)

        print ip_id, domain_id
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
    header = False
    infile = None
    outfile = None

    matchers = {}
    repo = NetObjectRepo()

    def __init__(self, args):
        """ args - passed in by optparse """

        if type(args) != argparse.Namespace:
            return None
       
        self.matchers["ip"] = {
            "chk_func": self._is_valid_ip,
            "type": "ip",
        }
        self.matchers["url"] = {
            "rex": "(?:(?:https?|ftp)://)([^\/\s]+)",
            "type": "domain",
            "needs_resolution": True,
        }

        self.parse_args(args)

    def parse_args(self, args):
        self.infile = args.infile
        self.outfile = args.outfile
        
        if args.format == "CSV":
            self.delim = ","
        elif args.format == "TSV":
            self.delim = "\t"
        elif args.format == "delim":
            self.delim = args.delim

        for m in re.findall("AS\d+", args.filter):
            self.asn_filters.append(m)
        for m in re.findall("[A-Za-z]{2,3}[^\d]", args.filter):
            self.cc_filters.append(m)

    def domains_to_ips(self):

        print [domain_data["domain"] for domain_data in self.repo.get_domain_data()]
        ar = AsyncResolver([domain_data["domain"] for domain_data in self.repo.get_domain_data()])
        resolved = ar.resolve()

        for host, ip in resolved.items():
              if ip is None:
                  sys.stderr.write("%s could not be resolved.\n" % host)
              else:
                  self.repo.add_domain_ip(host, ip)

    def extract_matches(self):
        reader = csv.reader(self.infile, delimiter=self.delim)
        for line in reader:
            for cell in line:
                for m_key, m_dict in self.matchers.items():
                    if "chk_func" in m_dict and m_dict["chk_func"](cell):
                        self.repo.add(m_dict["type"], cell)
                    elif "rex" in m_dict:
                        for m in re.findall(m_dict["rex"], cell):
                            self.repo.add(m_dict["type"], m)

    def filter_matches(self):
        # TODO: this doesn't work for stdin! Need to write to temp file?
        self.infile.seek(0)
        readin = csv.reader(self.infile, delimiter=self.delim)
        
        for line in reader:
            for cell in line:
                for m_key, m_dict in self.matchers.items():
                    if "chk_func" in m_dict and m_dict["chk_func"](cell):
                        if self.repo.belongs_to(datatype=m_dict["type"], data=cell, asn_filters=[32400], cc_filters=['AU', 'IT']):
                            print line

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

    def process_file(self):
        self.found = self.extract_matches()
        self.domains_to_ips()
        self.add_asn_cc_info()
        self.filter_matches()
        #self.repo.dump()
        print self.found

if __name__ == "__main__":
    feedfilter = FeedFilter({})
    if not feedfilter:
        exit
