__all__ = ('BulkWhois')

import string
import telnetlib

class BulkWhois:
    leader = ""
    footer = ""
    server = ""
    port = -1
    delim = "\n"

    def __init__(self, 
                 leader="begin", 
                 footer="end", 
                 server="asn.shadowserver.org", 
                 port="43", 
                 delim="\n"):
        self.leader = leader
        self.footer = footer
        self.server = server
        self.port = port
        self.delim = delim

    def lookup(self, ip_list):
        result = ""

        try:
            tn = telnetlib.Telnet(self.server, self.port)   
            
            tn.write(self.format_list(ip_list))
            result = tn.read_all()
            print result

        except BufferError as e:
            print "Socket failed: " + e
    
    def format_list(self, ip_list):
        return self.delim.join([self.leader, self.delim.join(ip_list), 
               self.footer])

if __name__ == "__main__":
    bw = BulkWhois(leader="begin origin")
    lookups = ["www.racq.com.au", "www.shadowserver.org", "www.us.gov"]
    bw.lookup(lookups)

