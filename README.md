# IPv6 support for mTCP

This fork enables basic IPv6 support in mTCP. 

### Build instructions.

Please see the original `README` for build instructions.

Note that only one address is supported per interface. Your system will likely configure a link-local address for you; however, if you wish to use another address, please configure your interface with `ifconfig dpdkN inet6 del <addr>/<prefix>` and `ifconfig dpdkN inet6 add <addr>/<prefix>`.

### API changes

To use IPv6, simply use `AF_INET6` and `struct sockaddr_in6` instead of `AF_INET` and `struct sockaddr_in` in `mtcp_*()` functions. 

If you use `mtcp_bind()` on an IPv6 socket pointing to `in6addr_any`, the socket will be dual-stack.

### Examples

Use the `apps/example/epwget` and `apps/example/epserver` as usual.

### Notes

If you wish to add static IPv6 routes or ND entries, you can proceed as for IPv4 and add them to `config/routes.conf` and `config/arp.conf` (you can mix IPv4 and IPv6 in those files). Router Advertisements are not yet supported.

### Contact

Yoann Desmouceaux [yd814 at ic dot ac dot uk]
