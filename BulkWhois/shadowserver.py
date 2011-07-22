__all__ = ('BulkWhoisShadowserver')

from bulkwhois import BulkWhois

class BulkWhoisShadowserver(BulkWhois):

    def __init__(self, **kwargs):
            super(BulkWhoisShadowserver, self).__init__(**kwargs)
            self.server = "asn.shadowserver.org"
            self.leader = "begin origin"

    def get_records(self, ip_list):
        raw = self._lookup(ip_list)
        print raw

if __name__ == "__main__":
    lookups = ["201.21.203.254", "192.168.0.10", "203.20.1.2"]
    bw = BulkWhoisShadowserver()
    print "Server: " + bw.server
    print "Port: " + bw.port
    print "Leader: " + bw.leader
    print "Footer: " + bw.footer
    print bw.raw_lookup(lookups)

