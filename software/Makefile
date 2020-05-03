.PHONY: all

TARGET = pew
SHAREDLIB = fake_sleep
CRYPT = crypt

all:
	gcc $(TARGET).c -o $(TARGET)

secure:
	gcc -g -O2 -Wl,-z,relro,-z,now -fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2 $(TARGET).c -o $(TARGET)

objects:
	gcc -c *.c

fakesleep:
	gcc -fPIC -shared $(SHAREDLIB).c -o $(SHAREDLIB).so -ldl

crypt:
	gcc $(CRYPT).c -o $(CRYPT)

clean:
	rm -f $(TARGET) *.o $(SHAREDLIB).so $(CRYPT)
