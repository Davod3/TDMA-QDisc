CC=gcc
CFLAGS=-Wall -Wextra -std=c99 -I /usr/include/libnl3
LIBS=-lnl-3 -lnl-genl-3

SRC=netcntl.c cmdline.c
OBJ=$(SRC:.c=.o)
EXE=netcntl

all: $(EXE)

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LIBS)

%.o: %.c netcntl.h
	$(CC) $(CFLAGS) -c -o $@ $<

gengetopt:
	gengetopt < tdma.ggo

build_venv:
	python3 -m venv graph_env
	source graph_env/bin/activate
	pip3 install -r requirements.txt

clean:
	rm -f $(OBJ) $(EXE)
