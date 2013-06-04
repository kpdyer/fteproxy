FTE
===

Format-Transforming Encryption (FTE)

QUICKSTART  
----------

We have the following six variables that define the FTE network configuration.  
  
CLIENT\_IP - The IP address of the FTE client  
CLIENT\_PORT - The TCP port the client will listen on  
SERVER\_IP - The IP address of the FTE server  
SERVER\_PORT - The TCP port the server will listen on  
PROXY\_IP - The IP address of the socks proxy  
PROXY\_PORT - The TCP port of the socks proxy  

PROXY\_CLIENT <-> CLIENT\_IP:CLIENT\_PORT <-> ||CENSOR|| <-> SERVER\_IP:SERVER\_PORT <-> PROXY\_IP:PROXY\_PORT <-> ||INTERNET||

Typically we will have the FTE client and server running on different systems. However, for testing purposes it is acceptable for CLIENT\_IP == SERVER\_IP.

1. Extract the correct tar file for your arch:  
$ tar zxvf fte_relay-VERSION.PLATFORM.ARCH.tar.gz

2. Enter the extracted directory:  
$ cd fte_relay-VERSION.PLATFORM.ARCH

3. Start a SOCKS proxy on PROXY\_IP:PROXY\_PORT. We like: http://www.inet.no/dante/.  Using OpenSSH's SOCKS proxy will also work, or use the Tor client's proxy.

4. On the server, start the FTE relay:  
$ ./bin/fte\_relay --mode server --server\_ip SERVER\_IP --server\_port SERVER\_PORT --proxy\_ip PROXY\_IP --proxy\_port PROXY\_PORT

5. On the client, start the FTE relay:  
$ ./bin/fte\_relay --mode client --client\_ip CLIENT\_IP --client\_port CLIENT\_PORT --server\_ip SERVER\_IP --server\_port SERVER\_PORT

6. On the client, test that everything works:  
$ curl --socks5 CLIENT\_IP:CLIENT\_PORT google.com

CHANGING FORMATS
-----------------------------
The FTE software ships with a range of formats, specified in the form:  source-protocol-direction.

source = {bro,yaf,l7,intersection,learned_ag}  
protocol = {http,ssh}  
direction = {request,response}  

The default languages are insersection-http-request/intersection-http-response. The intersection-http-request language was created by taking the intersection of the bro, yaf, and l7 http-request languages. The intersection-http-response language was created similarly for the opposite direction.

In order to change the format used by the FTE system, use the "--upstream-format" and "--downstream-format" command-line arguments when starting the client. For a list of available formats, invoke the "--help" argument.


EXAMPLE USAGES
-------------------------
Start the FTE client as a background process:  
$ ./bin/fte\_relay --mode client --client\_ip CLIENT\_IP --client\_port CLIENT\_PORT  --server\_ip SERVER\_IP --server\_port SERVER\_PORT &

Request that the background FTE client process terminates cleanly:  
$ ./bin/fte\_relay --mode client --stop

Start the FTE server as a background process:  
$ ./bin/fte\_relay --mode server --server\_ip SERVER\_IP --client\_port SERVER\_PORT --proxy\_ip PROXY\_IP --proxy\_port PROXY\_PORT &

Request that the background FTE server process terminates cleanly:  
$ ./bin/fte\_relay --mode server --stop

TOR BUNDLES
-----------
Currently, we have made pre-configured Tor browser bundles available for 32- and 64-bit Linux, as well as Mac OSX.  These have been tested on the respective target system and are set to connect to our FTE-enabled bridge, located at the University of Wisconsin-Madison.  By default, the Tor bundles use the intersection-http language, but may be changed to use any of the above languages.  Based on our testing, the intersection-http language provides the best balance between overall speed and ability to circumvent just about all protocol identification systems.  

FTE-enabled TorBundles can be found [here] (https://github.com/redjack/FTE/tree/master/TorBundles)

SECURITY CONSIDERATIONS
------------------------------------------------
The FTE software has several unit tests and the underlying encryption scheme has been checked for correctness and security.  In addition, the software has passed all stress tests and has been running constantly for over a month on one of our test systems.  There are, however, several features that have not been implemented yet:  

1. The software uses a single hard-coded encryption key.  In the future, we hope to implement session keys and a secure key exchange protocol.
2. Code to convert custom regular expressions into DFAs that are input into FTE has not been added yet, but is available upon request.
3. There has not been extensive testing again malicious inputs for buffer overflows or other memory corruption attacks.

While we believe this software is safe for most current uses, please keep these issues in mind when applying the software in your particular environment.  Overall, we believe the current FTE release is at least as secure as obfs2 and obfs3 protocols in the ObfsProxy pluggable transport.
