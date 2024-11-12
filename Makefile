build:
	gcc ipk-sniffer.c -lpcap -o ipk-sniffer
clean:
	rm ipk-sniffer