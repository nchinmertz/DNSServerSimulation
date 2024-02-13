import secrets
import socket
from datetime import datetime




class Server:
    def __init__(self, website_name, host, port=53):
        self.website_name = website_name
        self.address = (host, port)
        self.answers = []
        self.additions = []
        self.ip_addresses = []

    @staticmethod
    def parse_int(byts, ln):
        return int.from_bytes(byts[:ln], 'big'), byts[ln:]

    def parse_rr_name(self, byts, full_response):  # modifed from https://stackoverflow.com/questions/32309177/how-do-we-do-dns-query-in-python
        domain_parts = []
        while True:
            if byts[0] // 64:  # OFFSET pointer
                assert byts[0] // 64 == 3, byts[0]
                offset, byts = self.parse_int(byts, 2)
                offset = offset - (128 + 64) * 256  # clear out top 2 bits
                label, _ = self.parse_rr_name(full_response[offset:], full_response)
                domain_parts.append(label)
                break
            else:  # regular NAME
                ln, byts = self.parse_int(byts, 1)
                label, byts = byts[:ln], byts[ln:]
                if not label:
                    break
                domain_parts.append(label.decode())
        return '.'.join(domain_parts), byts

    def parse_response(self, response):
        qdcount = int.from_bytes(response[4:6], 'big')
        ancount = int.from_bytes(response[6:8], 'big')
        nscount = int.from_bytes(response[8:10], 'big')
        arcount = int.from_bytes(response[10:12], 'big')
        remaining = response[12:]
        # parse questions, eats up question section so non_header_section starts at answer
        for question in range(qdcount):
            domain, remaining = self.parse_rr_name(remaining, response)
            qtype, remaining = self.parse_int(remaining, 2)
            qclass, remaining = self.parse_int(remaining, 2)

        # parse answer section
        for answer in range(ancount):
            domain, remaining = self.parse_rr_name(remaining, response)
            rtype, remaining = self.parse_int(remaining, 2)
            rclass, remaining = self.parse_int(remaining, 2)
            ttl, remaining = self.parse_int(remaining, 4)
            rdlength, remaining = self.parse_int(remaining, 2)
            rdata, remaining = remaining[:rdlength], remaining[rdlength:]
            if rtype == 1:  # IPv4 address
                rdata = '.'.join(str(x) for x in rdata)
            if rtype in (2, 5, 12, 15):  # NS, CNAME, MX
                rdata, _ = self.parse_rr_name(rdata, response)
            answer = (rtype, domain, ttl, rdata)
            self.answers.append(answer)

        # eat the bytes of the authority section so can start parsing the additions section
        for authority in range(nscount):
            domain, remaining = self.parse_rr_name(remaining, response)
            rtype, remaining = self.parse_int(remaining, 2)
            rclass, remaining = self.parse_int(remaining, 2)
            ttl, remaining = self.parse_int(remaining, 4)
            rdlength, remaining = self.parse_int(remaining, 2)
            rdata, remaining = remaining[:rdlength], remaining[rdlength:]

        # parse additional section
        for addition in range(arcount):
            domain, remaining = self.parse_rr_name(remaining, response)
            rtype, remaining = self.parse_int(remaining, 2)
            rclass, remaining = self.parse_int(remaining, 2)
            ttl, remaining = self.parse_int(remaining, 4)
            rdlength, remaining = self.parse_int(remaining, 2)
            rdata, remaining = remaining[:rdlength], remaining[rdlength:]
            if rtype == 1:  # IPv4 address
                rdata = '.'.join(str(x) for x in rdata)
                addition = (rtype, domain, ttl, rdata)
                self.additions.append(addition)
                self.ip_addresses.append(rdata)

    def make_request(self, line2str, qdcount, ancount, nscount, arcount, qtype, qclass):
        # makes the header
        header_id = secrets.token_bytes(2)  # can sub in any two random bytes
        line2 = []
        for i in range(0, len(line2str), 8):
            line2.append(int(line2str[i:i + 8], 2))
        header = header_id + bytes(line2) + qdcount + ancount + nscount + arcount
        # Question
        qname = b""
        for label in self.website_name.rstrip('.').split('.'):
            qname += int.to_bytes(len(label), length=1, byteorder='big')
            qname += label.encode()
        qname += b'\0'  # terminates with the zero length octet for the null label of the root.
        qtype = int.to_bytes(qtype, length=2, byteorder='big')
        question = qname + qtype + qclass
        request = header + question
        return request

    def run(self):
        request = self.make_request(line2str="0000000000000000",
                                    qdcount=b"\0\1", ancount=b"\0\0", nscount=b"\0\0", arcount=b"\0\0",
                                    qtype=1, qclass=b'\0\1')

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(request, self.address)
        s.settimeout(10000)
        try:
            response, serveraddr = s.recvfrom(512)
        except socket.timeout:
            return 0

        self.parse_response(response)
        return 1
