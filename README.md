# OAuth for MyProxy

This is an adapted version of [NCSA's OA4MP](https://github.com/ncsa/OA4MP)
adding among others a `/getproxy` endpoint.

It requires the also adapted version of the [security-lib](https://github.com/rcauth-eu/security-lib).

Both are requirements for the RCauth.eu codebase, including the RCauth
[Delegation Server](https://github.com/rcauth-eu/aarc-delegation-server),
[MasterPortal](https://github.com/rcauth-eu/aarc-master-portal),
[demo VO-portal](https://github.com/rcauth-eu/aarc-vo-portal) and
[SSH Key portal](https://github.com/rcauth-eu/aarc-ssh-portal).

## Prerequisites

* Java 8+ (OpenJDK 8 and 10 are both supported for building)
* [Maven](https://maven.apache.org/) 3.5+

## Compiling and installing

1. Compile and install the adapted version of the [security-lib](https://github.com/rcauth-eu/security-lib) dependency.

2. Check out the right RCauth-based branch, see the different RCauth components for the required versions.  
   For example:

        git checkout 4.2-RCauth

   *Make sure to use the same branch or tag for the OA4MP and security-lib components !!*

3. Compile and install the OA4MP itself

        mvn clean package install

## Docs

http://grid.ncsa.illinois.edu/myproxy/oauth/

## Background and further reading

https://wiki.nikhef.nl/grid/RCauth.eu_and_MasterPortal_documentation
