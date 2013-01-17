CC=gcc
EXEC=cipher_buffer
FILES= ./src/main.c ./src/gen_keyRSA.c ./src/cipher_buffer.c ./src/gen_key.c ./src/utils.c
CFLAGS= -ggdb -O0 -Wall
LDFLAGS= -L ./lib/
LIBS= ./lib/libpolarssl-x86_64.a
OBJS=$(FILES:.c=.o)

all: $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o ./bin/$(EXEC) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf ./src/*.o
	rm -f ./bin/$(EXEC)
	rm -f ./rsa.priv
	rm -f ./rsa.pub
