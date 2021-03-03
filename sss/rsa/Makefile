# add all source files
SRCS = $(wildcard *.c)
OBJS = $(SRCS: .c = .o)

# set compiler
CC = gcc
CFLAGS = -O2 -Wall

# set compile list
OUTPUT1 = auth
OUTPUT2 = keygen

# all in one list
OUTPUTLIST = $(OUTPUT1) $(OUTPUT2)

all : $(OUTPUTLIST)

# compiler targets
$(OUTPUT1) : $(OBJS)
	@$(CC) $^ -o $@ -D_$(shell echo $(@)|tr a-z A-Z)_

$(OUTPUT2) : $(OBJS)
	@$(CC) $^ -o $@ -D_$(shell echo $(@)|tr a-z A-Z)_

%.o : %.c
	@$(CC) -c $< $(CCFLAGS) $(IPATH)

clean:
	@rm $(OUTPUTLIST) plaintext.txt ciphertext.txt publicKey.txt privateKey.txt publicKey privateKey
.PHONY:clean
