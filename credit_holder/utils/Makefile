CC = gcc
INCL = -I/home/guoang/leon/credit_holder -I/home/guoang/leon/include
LIB = -L/home/guoang/leon -L/home/guoang/leon/credit_holder

all: cdloadkeys cdgetuserkey cdgetrolekey cdgetslkey cdcreateuserkey cdcreaterolekey cdcreateslkey

cdloadkeys: cdloadkeys.c
	$(CC) -o $@ cdloadkeys.c $(INCL) $(LIB) -lcd -lutpm -lkeyutils 

cdgetuserkey: cdgetuserkey.c
	$(CC) -o $@ cdgetuserkey.c $(INCL) $(LIB) -lcd -lutpm -lkeyutils 

cdgetrolekey: cdgetrolekey.c
	$(CC) -o $@ cdgetrolekey.c $(INCL) $(LIB) -lcd -lutpm -lkeyutils 

cdgetslkey: cdgetslkey.c
	$(CC) -o $@ cdgetslkey.c $(INCL) $(LIB) -lcd -lutpm -lkeyutils 

cdcreateuserkey: cdcreateuserkey.c
	$(CC) -o $@ cdcreateuserkey.c $(INCL) $(LIB) -lcd -lutpm -lkeyutils 

cdcreaterolekey: cdcreaterolekey.c
	$(CC) -o $@ cdcreaterolekey.c $(INCL) $(LIB) -lcd -lutpm -lkeyutils 

cdcreateslkey: cdcreateslkey.c
	$(CC) -o $@ cdcreateslkey.c $(INCL) $(LIB) -lcd -lutpm -lkeyutils 
