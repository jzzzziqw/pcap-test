# Makefile for pcap program

# Compiler
CC = gcc

# Compiler and linker flags
CFLAGS = -I/usr/local/include -L/usr/local/lib -lnet -lpcap

# Target executable
TARGET = pcap

# Source files
SRCS = pcap.c

# Default target
all: $(TARGET)

# Link the target executable
$(TARGET): $(SRCS)
	$(CC) -o $(TARGET) $(SRCS) $(CFLAGS)

# Clean up build files
clean:
	rm -f $(TARGET)

# Phony targets
.PHONY: all clean


