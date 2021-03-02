
CC = gcc
CFLAGS = -O2 -Wall
OBJS = bn.o keys.o rsa.o rsatest.o

rsatest: $(OBJS)

test: rsatest
	./rsatest

clean:
	rm -f rsatest *.o plaintext.txt ciphertext.txt publicKey.txt privateKey.txt
