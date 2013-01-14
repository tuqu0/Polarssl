CC=gcc
EXEC=gen_key
FILES= ./src/main.c ./src/gen_key.c
CFLAGS= -ggdb -O0 -Wall
LDFLAGS= -L ./lib/
LIBS= ./lib/libpolarssl64bits.a
OBJS=$(FILES:.c=.o)

all: $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o ./bin/$(EXEC) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf ./src/*.o
	rm -f ./bin/$(EXEC)
