CC = gcc
FLAG = 
INCL = -I/home/guoang/leon/include

all: credit_holder.o lib

credit_holder.o: credit_holder.c
	$(CC) -c credit_holder.c $(INCL)

lib: credit_holder.o
	$(CC) -shared -o libcd.so credit_holder.o
	ar -r libcd.a credit_holder.o

install: lib
	ln -s libcd.so /usr/local/lib/libcd.so

clean:
	rm -rf ./*.so ./*.a ./*.o
