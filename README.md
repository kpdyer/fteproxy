FTE
===

Format-Transforming Encryption (FTE)

QUICKSTART
=============================
We have the following six variables that define the FTE network configuration.

CLIENT_IP - The IP address of the FTE client
CLIENT_PPORT - The TCP port the client will listen on
SERVER_IP - The IP address of the FTE server
SERVER_PORT - The TCP port the server will listen on
PROXY_IP - The IP address of the socks proxy
PROXY_PORT - The TCP port of the socks proxy

PROXY_CLIENT <-> CLIENT_IP:CLIENT_PORT <-> SERVER_IP:SERVER_PORT <-> PROXY_IP:PROXY_PORT <-> ||INTERNET||

Typically we will have the FTE client and server running on different systems. However, for testing purposes it is acceptable for CLIENT_IP == SERVER_IP.

1. Extract the correct tar file for your arch:
$ tar zxvf fte_relay-VERSION.PLATFORM.ARCH.tar.gz

2. Enter the extracted directory:
$ cd fte_relay-VERSION.PLATFORM.ARCH

3. Start a SOCKS proxy on PROXY_IP:PROXY_PORT. We like: http://www.inet.no/dante/

4. On the server, start the FTE relay:
$ ./bin/fte_relay --mode server --server_ip SERVER_IP --server_port SERVER_PORT --proxy_ip SOCKS_IP --proxy_port SOCKS_PORT

5. On the client, start the FTE relay:
$ ./bin/fte_relay --mode client --client_ip CLIENT_IP --client_port CLIENT_PORT --server_ip SERVER_IP --server_port SERVER_PORT

6. On the client, test that everything works:
$ curl --socks5 CLIENT_IP:CLIENT_PORT google.com

CHANGING FORMATS
=============================
The FTE software ships with a range of formats, specified in the form: source-protocol-direction

source = {bro,yaf,l7,intersection,learned_ag}
protocol = {http,ssh}
direction = {request,response}

The default languages are insersection-http-request/intersection-http-response. The intersection-http-request language was created by taking the intersection of the bro, yaf, and l7 http-request languages. The intersection-http-response language was created similarly.

In order to change the format used by the FTE system, use the "--upstream-format" and "--downstream-format" command-line arguments when starting the client. For a list of available formats, invoke the "--help" argument.


EXAMPLE USAGES
=============================

Start the FTE client as a background process:
$ ./bin/fte_relay --mode client --client_ip CLIENT_IP --client_port CLIENT_PORT  --server_ip SERVER_IP --server_port SERVER_PORT &

Request that the background FTE client process terminates cleanly:
$ ./bin/fte_relay --mode client --stop

Start the FTE server as a background process:
$ ./bin/fte_relay --mode server --server_ip SERVER_IP --client_port SERVER_PORT --proxy_ip PROXY_IP --proxy_port PROXY_PORT &

Request that the background FTE server process terminates cleanly:
$ ./bin/fte_relay --mode server --stop

