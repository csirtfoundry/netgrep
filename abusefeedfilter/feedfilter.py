__all__ = ('FeedFilter')

from delim_filter import DelimFilter
import argparse
import re
import csv
import socket
from bulkwhois.shadowserver import BulkWhoisShadowserver
#import XMLFilter from xml_filter

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
    file = ""

    matchers = {}
    found = {}
  
    def __init__(self, args):
        """ args - passed in by optparse """

        if type(args) != argparse.Namespace:
            return None
       
        self.matchers["ip"] = {
            "chk_func": self.is_valid_ip,
            "store_key": "ip",
        }
        self.matchers["url"] = {
            "rex": "(?:(?:https?|ftp)://)([^\/\s]+)",
            "store_key": "domain",
            "needs_resolution": True,
        }

        self.parse_args(args)

    def parse_args(self, args):
        self.file = args.file
        
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

    def domain_to_ip(self):
        pass

    def extract_matches(self):
        matches = {}

        reader = csv.reader(self.file, delimiter=self.delim)
        for line in reader:
            for cell in line:
                for m_key, m_dict in self.matchers.items():
                    if "chk_func" in m_dict and m_dict["chk_func"](cell):
                        matches.setdefault(cell, {})[m_dict["store_key"]] = [cell]
                    elif "rex" in m_dict:
                        for m in re.findall(m_dict["rex"], cell):
                            matches.setdefault(cell, {})[m_dict["store_key"]] = [m]
        return matches

    def is_valid_ip(self, ip):
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
            bw = BulkWhoisShadowserver()
            ip_list = []
            for key, vals in self.found.items():
                if "ip" in vals:
                    for v in vals["ip"]:
                        ip_list.append(v)
            return bw.lookup_ips(ip_list)
        
        asn_info = asn_lookup()
        
        for key, vals in self.found.items():
            if "ip" in vals:
                for ip in vals["ip"]:
                    if ip in asn_info:
                        for field in ["cc", "asn"]:
                            if field in asn_info[ip]:
                                self.found[key][field] = asn_info[ip][field] 


        #bw.lookup_ips([v["ips"] for k, v in self.found])

    def process_file(self):
        self.found = self.extract_matches()

        self.add_asn_cc_info()
        print self.found

if __name__ == "__main__":
    feedfilter = FeedFilter({})
    if not feedfilter:
        exit
