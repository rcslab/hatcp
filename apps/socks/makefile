CC       = clang
CFLAGS   = -Wall -I/usr/local/include -g -x c -O2 -DSOMIGRATION -DSMCP 	#-DANTIVIRUS
LDFLAGS  = -L/usr/local/lib -lev -lmemstat -pthread -lkvm 
OBJS = utils.o netutils.o server.o client.o socks.o ht.o hosts.o stats.o app.o main.o
TARGET   = socks

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%o: %.cc 
	$(CC) $(CFLAGS) -x c -o $@ -c $<

clean:
	rm *.o
