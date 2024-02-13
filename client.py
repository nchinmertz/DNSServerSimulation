import secrets
import socket


class Client:
    def __init__(self):
        self.website_name = input("Website Name: ")

    def tcp_connect(self, ip_address):
        message = f"GET / HTTP/1.1\r\nHost:www.{self.website_name}\r\n\r\n".encode()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10000)
        try:
            s.connect((ip_address, 80))
            s.sendto(message, (ip_address, 80))
            response = s.recvfrom(512)
            response = repr(response)
        except socket.timeout:
            return 0, 0
        with open(f"{self.website_name[:-4]}.html", "w") as file:
            file.write(response)

    def make_request(self):
        line2str = "0000000100000000"
        qdcount = b"\0\1"
        ancount = b"\0\0"
        nscount = b"\0\0"
        arcount = b"\0\0"
        qtype = 1
        qclass = b'\0\1'
        header_id = secrets.token_bytes(2)  # can sub in any two random bytes
        line2 = []
        for i in range(0, len(line2str), 8):
            line2.append(int(line2str[i:i + 8], 2))
        header = header_id + bytes(line2) + qdcount + ancount + nscount + arcount
        qname = b""
        for label in self.website_name.rstrip('.').split('.'):
            qname += int.to_bytes(len(label), length=1, byteorder='big')
            qname += label.encode()
        qname += b'\0'  # terminates with the zero length octet for the null label of the root.
        qtype = int.to_bytes(qtype, length=2, byteorder='big')
        question = qname + qtype + qclass
        request = header + question
        return request
