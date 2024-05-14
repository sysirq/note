# Connections

In Linux,a socket is actually composed of two socket structures.

### Socket structures

There are two main socket strucures in Linux:general BSD sockets and IP specific INET sockets.They are strongly interrelated;a BSD socket has an INET socket as a data member and an INET socket has a BSD socket as its owner.

### Sockets and Routing

The transport protocols call the ip_route_connect() function to determine the route from host to host during the connection process;

# 资料

Networking

https://linux-kernel-labs.github.io/master/labs/networking.html#linux-networking

Linux IP Networking

http://www.cs.unh.edu/cnrg/people/gherrin/linux-net.html