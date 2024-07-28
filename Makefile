CC = gcc

TARGET = pcap-test

SRC = osi.c

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) -lpcap

clean:
	rm -f $(TARGET)

.PHONY: all clean