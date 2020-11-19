CC=gcc
CFLAGS=-Wall -ggdb

default: oss user

shared.o: shared.c oss.h
	$(CC) $(CFLAGS) -c shared.c

blockedq.o: blockedq.c blockedq.h
	$(CC) $(CFLAGS) -c blockedq.c

oss: oss.c oss.h blockedq.o
	$(CC) $(CFLAGS) oss.c blockedq.o -o oss

user: user.c oss.h
	$(CC) $(CFLAGS) user.c -o user

clean:
	rm -f oss user *.o
