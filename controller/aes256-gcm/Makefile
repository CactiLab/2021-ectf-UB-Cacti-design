
CC = gcc
CFLAGS = -O2 -Wall
OBJS = aestest.o gcm.o aes.o aes-gcm.o

aestest: $(OBJS)

test: aestest
	./aestest

clean:
	rm -f aestest *.o 
