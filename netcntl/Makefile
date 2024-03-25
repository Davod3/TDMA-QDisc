CC=gcc
CFLAGS=-Wall -Wextra -std=c99 -I /usr/include/libnl3
LIBS=-lnl-3 -lnl-genl-3

SRC=netcntl.c cmdline.c
OBJ=$(SRC:.c=.o)
EXE=netcntl

all: $(EXE)
	gengetopt < tdma.ggo

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LIBS)

%.o: %.c netcntl.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(EXE)
