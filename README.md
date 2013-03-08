A packet capturing kernel module based on netfilter along with a port of the implement in userspace using libpcap.

Files of interest - packet_filter.c, libpcap_filter.c

To run the module:

As user in pwd:
	make clean
	make

As su in pwd:
	insmod packet_filter.ko port="<name of port>" sourceip="<source ip address to filter>" time=<time in ms>

Output is available at:
	TTY
	/var/log/kern.log

To see output in on console in real time:

	Note: The output will be available only in TTY Terminal and not in X Window terminals.
	
	As superuser:

		To insert module:
			insmod packet_filter.ko port="<name of port>" sourceip="<source ip address to filter>" time=<time in ms>
			
			//Output will be displayed

		To remove the module:

			rmmod packet_counter



