CFLAGS += -lcrypto -fgnu89-inline
#LDFLAGS += -lcrypto

gduth3c: main.o auth.o mem_clr.o md5_one.o md5_dgst.o
	$(CC) $(LDFLAGS) $^ -o $@

main.o: main.c auth.h
	$(CC) $(CFLAGS) -c -o $@ $<

auth.o: auth.c auth.h
	$(CC) $(CFLAGS) -c -o $@ $<

mem_clr.o: mem_clr.c
	$(CC) $(CFLAGS) -c -o $@ $<

md5_one.o: md5_one.c
	$(CC) $(CFLAGS) -c -o $@ $<

md5_dgst.o: md5_dgst.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean :
	rm -f gduth3c *.o
