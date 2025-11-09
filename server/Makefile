CC = $(CROSS_COMPILE)gcc
CFLAGS = -DUSE_AESD_CHAR_DEVICE=1

all: aesdsocket
default: aesdsocket

aesdsocket: aesdsocket.c
	$(CC) $(CFLAGS) -I./include -o aesdsocket aesdsocket.c 

clean:
	rm -f aesdsocket