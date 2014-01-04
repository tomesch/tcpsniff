all:
	@gcc -o tcpsniff tcpsniff.c -lpcap
clean:
	@rm tcpsniff

