CC=gcc
NAME=curfew
OPTIM=-O3
DEBUG=-g
WARN=-Wall -Wextra -pedantic
OUT=-o $(NAME)
LIB=`pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0`
DEF=-D _GNU_SOURCE
STD=-std=c99
DIR=/usr/local/bin/

curfew: curfew.c
	$(CC) curfew.c $(OUT) $(WARN) $(LIB) $(OPTIM) $(DEF) $(STD)

debug: c2.c
	$(CC) curfew.c $(OUT) $(WARN) $(LIB) $(OPTIM) $(DEF) $(STD) $(DEBUG)

clean:
	rm -vfi ./$(NAME)

install:
	install -m 557 $(NAME) $~$(DIR)

uninstall:
	rm -vi $~$(DIR)$(NAME)
