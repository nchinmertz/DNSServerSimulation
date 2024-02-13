from client import Client
from server import Server


ROOT_IP_ADRS = ["198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230", "192.5.5.241",
                "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
                "202.12.27.33"]


def DNS_server(website_name, ip_addresses):
    for ip in ip_addresses:
        dns = Server(website_name, ip, 53)
        retval = dns.run()
        if retval == 1:
            return dns


def parse_int(byts, ln):
    return int.from_bytes(byts[:ln], 'big'), byts[ln:]


def parse_rr_name(byts, full_response):  # modifed from https://stackoverflow.com/questions/32309177/how-do-we-do-dns-query-in-python
    domain_parts = []
    while True:
        if byts[0] // 64:  # OFFSET pointer
            assert byts[0] // 64 == 3, byts[0]
            offset, byts = parse_int(byts, 2)
            offset = offset - (128 + 64) * 256  # clear out top 2 bits
            label, _ = parse_rr_name(full_response[offset:], full_response)
            domain_parts.append(label)
            break
        else:  # regular NAME
            ln, byts = parse_int(byts, 1)
            label, byts = byts[:ln], byts[ln:]
            if not label:
                break
            domain_parts.append(label.decode())
    return '.'.join(domain_parts), byts


def parse_client_request(request):
    qdcount = int.from_bytes(request[4:6], 'big')
    remaining = request[12:]
    # parse questions
    for question in range(qdcount):
        domain, remaining = parse_rr_name(remaining, request)
        qtype, remaining = parse_int(remaining, 2)
        qclass, remaining = parse_int(remaining, 2)
    return domain


def main():
    client = Client()
    request = client.make_request()
    domain = parse_client_request(request)
    dns_root = DNS_server(domain, ROOT_IP_ADRS)
    dns_tld = DNS_server(domain, dns_root.ip_addresses)
    dns_auth = DNS_server(domain, dns_tld.ip_addresses)
    client.tcp_connect(dns_auth.answers[0][3])
    print(f"Root server IP address: {dns_root.address[0]}")
    print(f"TLD server IP address: {dns_tld.address[0]}")
    print(f"Authoritative server IP address: {dns_auth.address[0]}")
    print(f"HTTP server IP address: {dns_auth.answers[0][3]}")

main()
