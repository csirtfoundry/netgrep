import telnetlib

class BulkWhois(object):
    """
        Query a list of IPs from a bulk whois server. This class is not
        designed to be called directly: rather, use one of the subclass
        interfaces to specific bulk whois servers such as Cymru or
        Shadowserver.
    """


    leader = ""
    footer = ""
    server = ""
    port = -1
    record_delim = ""
    field_delim = ""
    has_result_header = False
    field_list = []

    def __init__(self, 
                 leader="begin", 
                 footer="end", 
                 server="asn.shadowserver.org", 
                 port="43", 
                 record_delim="\n",
                 field_delim="|",
                 has_result_header=False):
        self.leader = leader
        self.footer = footer
        self.server = server
        self.port = port
        self.record_delim = record_delim
        self.field_delim = field_delim
        self.has_result_header = has_result_header

    def _lookup(self, ip_list):
        result = ""
        query = self._format_list(ip_list)

        try:
            tn = telnetlib.Telnet(self.server, self.port)   
            tn.write(query)
            result = tn.read_all()
        except Exception as e:
            raise e
    
        return result

    def raw_lookup(self, ip_list):
        """
            Get the exact output returned by whois server as a string
        """
        return self._lookup(ip_list)

    def get_records(self, ip_list):
        raw = self._lookup(ip_list)

        records = {}

        for line_num, line in enumerate(self.record_delim.split(raw)):
            if line_num == 0 and self.has_result_header:
                next

            for field_num, field in enumerate(self.field_delim.split(line)):
                if self.fields and length(self.fields) > field_num:
                    records.get(self.fields[field_num], field)
                else
                    records.get(field_num, field)

    def _format_list(self, ip_list):
        return self.record_delim.join([self.leader, self.record_delim.join(ip_list), \
               self.footer]) + self.record_delim

 
if __name__ == "__main__":
    lookups = ["201.21.203.254", "192.168.0.10", "203.20.1.2"]
    bw = BulkWhois(leader="begin origin")
    print bw.raw_lookup(lookups)
    print bw.get_records(lookups)

    bw2 = BulkWhois(leader="begin\nverbose", server="asn.cymru.com")
    print bw2.raw_lookup(lookups)
    print bw2.get_records()


