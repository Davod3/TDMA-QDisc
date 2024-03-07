CC=gcc
CFLAGS=-Wall -Wextra -std=c99

SRC=netcntl.c cmdline.c
OBJ=$(SRC:.c=.o)
EXE=netcntl

all: $(EXE)
	gengetopt < tdma.ggo

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c netcntl.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(EXE)
