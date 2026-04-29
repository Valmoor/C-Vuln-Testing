CC      = gcc
CFLAGS  = -Wall -g
TARGETS = main server

all: $(TARGETS)

main: src/main.c
	$(CC) $(CFLAGS) -o main src/main.c

server: src/server.c
	$(CC) $(CFLAGS) -o server src/server.c

clean:
	rm -f $(TARGETS)
