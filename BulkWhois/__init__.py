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
    fields = []

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

    def get_records_by_ip(self, ip_list):
        """
            Return a dictionary of lists indexed by IP address with whois 
            results.

            Ensure that the "ip" field exists in the fields array in the
            position of the IP address.
        """

        raw = self._lookup(ip_list)

        records = {}
        ip_index = self.field_names.index("ip")
        
        if "ip" not in self.field_names:
            raise ValueError("You need to include an 'ip' field in the field_names array.")

        for line_num, line in enumerate(raw.split(self.record_delim)):
            # some whois results have a header we'll throw away
            if line_num == 0 and self.has_result_header:
                next

            fields = line.split(self.field_delim)
            # lots of fields space padded
            fields = [field.strip() for field in fields]

            if len(fields) < len(self.field_names):
                # skip this line: malformed, or doesn't match out template
                pass
            else:
                records.setdefault(fields[ip_index], dict(zip(self.field_names, fields)))

        return records

    def _format_list(self, ip_list):
        return self.record_delim.join([self.leader, self.record_delim.join(ip_list), \
               self.footer]) + self.record_delim

 
if __name__ == "__main__":
    lookups = ["201.21.203.254", "203.21.203.254", "130.102.6.192", "192.168.0.10", "203.20.1.2", "200.200.200.200", "8.8.8.8"]
    bw = BulkWhois(leader="begin origin")
    bw.field_names=["ip", "asn", "bgp_prefix", "as_name", "cc", "register", "org_name"]
    print bw.raw_lookup(lookups)
    print bw.get_records_by_ip(lookups)

    bw2 = BulkWhois(leader="begin\nverbose", server="asn.cymru.com")
    bw2.field_names=["asn", "ip", "bgp_prefix", "cc", "registry", "allocated", "as_name"]
    print bw2.raw_lookup(lookups)
    print bw2.get_records_by_ip(lookups)


