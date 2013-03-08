Instructions to get the sample program in Libpcap running.


Download and Install the libpcap library.
Download from http://www.tcpdump.org/#latest-release
To Install, do the following:
1. Untar the contents in a folder.
2. do "sudo ./configure". If it throws errors, resolve them. You will most likely have to install additional software like flex and bison.
3. do "sudo make"
4. do "sudo make install"
5. then do "sudo ldconfig" this will config the library.


After this you can remove the uncompressed files if you want.


Create a directory and copy libpcap_filter.c file in it.
Compile using: gcc -Wall -pedantic pcap_main.c -lpcap
Run: ./a.out <num_packets>