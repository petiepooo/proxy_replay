LDFLAGS = -L/usr/lib -lpcap

all: proxy_replay

proxy_replay: proxy_replay.o hashmap.o
