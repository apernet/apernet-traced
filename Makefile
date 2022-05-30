CFLAGS=-O0 -g -Wall -Wextra
OBJS=main.o trace.o tun.o

.PHONY: all clean

all: $(OBJS)
	$(CC) $(CFLAGS) -o traced $(OBJS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f *.o