CFLAGS=-O0 -g -Wall -Wextra
OBJS=main.o trace.o tun.o inline.o config.tab.o config.yy.o
FLEX=flex
BISON=bison

.PHONY: all clean

all: $(OBJS)
	$(CC) $(CFLAGS) -o traced $(OBJS)

config.tab.c: config.y
	$(BISON) -d config.y

config.yy.c: config.l
	$(FLEX) -o config.yy.c config.l

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f *.o config.yy.c config.tab.c config.tab.h