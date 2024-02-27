This project is designed to simulate a DNS resolver. It starts by creating a Client object, which prompts the user to input a domain name. Then the Client constructs a request according to RFC 1035 specificaations to send to a DNS resolver.

As this is a simulation, the Client just passes the request to the Server object which will act as a DNS resolver. The Server object parses the request, retrieves the website name, and then generates a request to send to a root serverl. If no response is recieved within the timout period of 10 seconds the server will try another root server. This will continue until there is a response or no more servers left to try. After recieving a repsonse from the root server, the Server object will continue to generate and send requests traversing down the DNS hierarchy until it reaches the authoritative server. The response from the authoiratative server will contain the HTTP IP address which it will then send to the Client. The program will print out each server it contacted as well as the HTTP server. 

The Client will then establish a TCP connection with the HTTP IP address and saces the response as an HTML file named after the website. 

To run, execute `main.py` using Python3
