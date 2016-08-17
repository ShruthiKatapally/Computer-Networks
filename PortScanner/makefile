GCC=gcc

all: netcat_part.o 
	$(GCC) netcat_part.o -o netcat_part
	
netcat_part.o: netcat_part.c
	$(GCC) -c portScanner.c

clean:
	rm -rf *.o netcat_part output_file.txt
	gcc portScanner.c -lpcap -lm
