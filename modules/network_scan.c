/*The gethostbyname() function returns the binary IP address(es) corresponding to a
hostname and the getservbyname() function returns the port number corresponding
to a service name. The reverse conversions are performed by gethostbyaddr() and
getservbyport(). We describe these functions because they are widely used in existing
code. However, they are now obsolete. (SUSv3 marks these functions obsolete, and
SUSv4 removes their specifications.) New code should use the getaddrinfo() and
getnameinfo() functions (described next) for such conversions.

pg 1205 Linux programming interface*/