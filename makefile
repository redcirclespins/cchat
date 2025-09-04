CC      := gcc
CFLAGS  := -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wconversion -Wsign-conversion \
           -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes \
           -O2 -g -pipe -std=gnu11
LDFLAGS := -lssl -lcrypto
TARGETS := client server
OBJS    := func.o

all: $(TARGETS)

client: client.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
server: server.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGETS) *.o
.PHONY: all clean
