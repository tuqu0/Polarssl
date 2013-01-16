CC=gcc
EXEC=protect_buffer
FILES= ./src/main.c ./src/deriv_passwd.c ./src/protect_buffer.c ./src/utils.c
CFLAGS= -ggdb -O0
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
