CC       = clang
CFLAGS   = -Wall -I/usr/local/include -g -x c -O2\
	   -DHASH_MD5 -DPROTO_BATCHING -DPERF_PROFILING 
LDFLAGS  = -L/usr/local/lib -lev -lmd -lmemstat -pthread -lssl -lcrypto -lkvm
OBJS = 		utils.o netutils.o worker.o\
		server.o io.o acc.o stats.o\
		./plugin/plugin.o \
		./acc/chunk.o \
		./acc/compression.o \
		./acc/dedup.o \
		./acc/ht.o \
		./acc/lz4.o	\
		./acc/rbkp.o \
		./acc/skein/skein.o \
		./proto/http.o \
		app.o main.o
TARGET   = wanacc

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%o: %.cc 
	$(CC) $(CFLAGS)  -o $@ -c $<

clean:
	rm *.o
	rm ./acc/*.o
	rm ./plugin/*.o
	rm $(TARGET)


