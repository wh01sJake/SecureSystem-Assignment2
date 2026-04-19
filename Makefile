CC ?= cc

.PHONY: all
all: main rijndael.so

main: rijndael.o main.c
	$(CC) -o main main.c rijndael.o

rijndael.o: rijndael.c rijndael.h
	$(CC) -o rijndael.o -fPIC -c rijndael.c

rijndael.so: rijndael.o
	$(CC) -o rijndael.so -shared rijndael.o

.PHONY: test
test: rijndael.so
	python -m pytest tests/ -v

clean:
	rm -f *.o *.so
	rm -f main
