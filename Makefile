CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
TARGET := build/packet_demo
SOURCE := src/main.c

.PHONY: all run receiver sender clean

all: $(TARGET)

$(TARGET): $(SOURCE)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET) --help

receiver: $(TARGET)
	./$(TARGET) receive

sender: $(TARGET)
	./$(TARGET) send

clean:
	rm -rf build
