.PHONY: all

all:
	gcc *.c -o program

secure:
	gcc -g -O2 -Wl,-z,relro,-z,now -fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2 *.c -o program

objects:
	gcc -c *.c

clean:
	rm -f program *.o
