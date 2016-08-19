mymakefile: mysniffer.c sniffer_functions.c; gcc -o psniff sniffer_functions.c mysniffer.c -lpcap;
