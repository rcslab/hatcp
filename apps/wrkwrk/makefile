CC       = clang 
CFLAGS   = -Wall -I/usr/local/include -g -x c -O2
LDFLAGS  = -L/usr/local/lib -lev -lpthread
OBJS = http.o netutil.o stat.o utils.o socks.o trace.o wrkwrk.o 
TARGET   = wrkwrk

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%o: %.cc 
	$(CC) $(CFLAGS) -x c -o $@ -c $<

clean:
	rm *.o
