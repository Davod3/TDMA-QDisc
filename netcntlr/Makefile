CC=gcc
CFLAGS=-Wall -Wextra -std=c99 -I /usr/include/libnl3
LIBS=-lnl-3 -lnl-genl-3

SRC=netcntlr.c cmdline.c librtnetlink.c
OBJ=$(SRC:.c=.o)
EXE=netcntlr

all: $(EXE)

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LIBS)

%.o: %.c netcntlr.h
	$(CC) $(CFLAGS) -c -o $@ $<

gengetopt:
	gengetopt < tdma.ggo

build_venv:
	python3 -m venv graph_env
	source graph_env/bin/activate
	pip3 install -r requirements.txt

manage_qdisc:
	$(CC) -I. -I./include -c -o ./manage_qdisc.o ./manage_qdisc.c;
	$(CC) -I./include -c -o ./lib/librtnetlink.o ./lib/librtnetlink.c;
	ar rcs ./lib/librtnetlink.a ./lib/librtnetlink.o;
	$(CC) -o ./manage_qdisc ./manage_qdisc.o ./lib/librtnetlink.a;


clean:
	rm -f $(OBJ) $(EXE)
