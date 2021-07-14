LDFLAGS = -L/usr/lib -lpcap

all: proxy_replay

proxy_replay: proxy_replay.o hashmap.o

clean:
	rm proxy_replay.o hashmap.o proxy_replay
