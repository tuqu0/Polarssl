CC=gcc
EXEC=deriv_passwd
FILES= ./src/main.c ./src/deriv_passwd.c ./src/utils.c
CFLAGS= -ggdb
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
