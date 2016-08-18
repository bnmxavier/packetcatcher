mymakefile: mysniffer.c sniffer_clean.c sniffer_functions.c; gcc -o psniff sniffer_functions.c mysniffer.c -lpcap;gcc -o cleansniff sniffer_functions.c sniffer_clean.c -lpcap;
