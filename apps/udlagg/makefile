CC       = clang
CFLAGS   = -Wall -I/usr/local/include -g -x c -O2 
LDFLAGS  = -L/usr/local/lib -lev -lkvm -lpcap 
OBJS = utils.o netutils.o server.o udlagg.o app.o main.o
TARGET   = udlagg

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%o: %.cc 
	$(CC) $(CFLAGS) -x c -o $@ -c $<

clean:
	rm *.o
