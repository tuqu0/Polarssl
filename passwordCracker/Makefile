CC=gcc
EXEC=passwordCracker
FILES= ./src/main.c \
       ./src/utils.c \
       ./src/parser.c \
       ./src/crack.c \
       ./src/md5.c \
       ./src/sha256.c \
       ./src/sha512.c
CFLAGS= -ggdb
LDFLAGS= -L ./lib/
LIBS= ./lib/libpolarssl-i686.a
OBJS=$(FILES:.c=.o)

all: $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o ./bin/$(EXEC) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf ./src/*.o
	rm -f ./bin/$(EXEC)
