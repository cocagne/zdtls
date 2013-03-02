
all: client server

client: client.c zhelpers.h ssl_helpers.h
	gcc -o client client.c -lzmq -lssl

server: server.c zhelpers.h ssl_helpers.h
	gcc -o server server.c -lzmq -lssl
