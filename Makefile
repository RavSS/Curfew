curfew: curfew.c
	gcc curfew.c -o curfew -lpcap -lpthread -Wall -Wextra -pedantic -std=c89

clean:
	rm -f curfew

install:
	install -m 557 curfew $~/usr/bin/

uninstall:
	rm -f $~/usr/bin/curfew
