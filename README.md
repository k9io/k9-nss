# k9-nss #

### What is k9-nss ###


This is source code for a shared library that allows *nix (Linux, FreeBSD, etc) to 
"lookup" usernames and group information via the K9 API.  To use it,  do this:

* make
* cp libnss_k9.so.2 /lib/x86_64-linux-gnu/
* Add "k9" to the /etc/nsswitch.conf file

