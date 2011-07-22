__all__ = ('BulkWhoisCymru')

from bulkwhois import BulkWhois

class BulkWhoisCymru(BulkWhois):

    def __init__(self, **kwargs):
            super(BulkWhoisCymru, self).__init__(**kwargs)
            self.server = "asn.cymru.com"
            self.leader = "begin\nverbose"
            self.has_result_header = True

if __name__ == "__main__":
    lookups = ["201.21.203.254", "192.168.0.10", "203.20.1.2"]
    bw = BulkWhoisCymru()
    print "Server: " + bw.server
    print "Port: " + bw.port
    print "Leader: " + bw.leader
    print "Footer: " + bw.footer
    print bw.raw_lookup(lookups)
    print bw.get_records(lookups)

