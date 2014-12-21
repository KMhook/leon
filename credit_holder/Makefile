CC = gcc
FLAG = 
INCL = -I/home/guoang/leon/include

all: credit_holder.o lib

credit_holder.o: credit_holder.c
	$(CC) -c credit_holder.c $(INCL)

lib: credit_holder.o
	$(CC) -shared -o libcd.so credit_holder.o
	ar -r libcd.a credit_holder.o

install:
	ln -s /home/guoang/leon/credit_holder/libcd.so /usr/local/lib/libcd.so

uninstall:
	rm -rf /usr/local/lib/libcd.so

clean:
	rm -rf ./*.so ./*.a ./*.o
