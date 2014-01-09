all:
	@gcc -Wall -o tcpsniff tcpsniff.c -lpcap
clean:
	@rm tcpsniff

