CC=gcc
CFLAGS=-c -Wformat=0 -fno-stack-protector

all: configure_bridge bridge_app example_receive_packets

configure_bridge:
	$(CC) conf_packet.c  -L ../src/libs/ -lspw_eth_unix -o configure_bridge

example_receive_packets:
	$(CC) receive_packets.c  -L ../src/libs/ -lspw_eth_unix -o example_receive_packets

bridge_app:
	$(CC) spw_eth_test.c  -L ../src/libs/ -lspw_eth_unix -o bridge_app

cleanall:
	rm -rf *.o configure_bridge bridge_app example_receive_packets

clean:
	rm -rf *.o
