CC = $(CROSS_COMPILE)gcc
CFLAGS =

all: aesdsocket
default: aesdsocket

aesdsocket: aesdsocket.c
	$(CC) $(CFLAGS) -I./include -o aesdsocket aesdsocket.c 

clean:
	rm -f aesdsocket