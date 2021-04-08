all: sniffICMP.c snifTCP.c
	gcc sniffICMP.c -o sniffICMP -lpcap
	gcc snifTCP.c -o sniffTCP -lpcap
.PHONY: clean all
clean:
	rm -f sniffICMP sniffTCP
	
