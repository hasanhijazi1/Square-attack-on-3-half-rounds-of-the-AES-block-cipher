# Simple Makefile to build and run the AES project

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -O2 -std=c11
LDFLAGS :=

# Sources in this folder (do not recurse into subfolders)
SRCS := \
  aes-128_enc.c \
  keygen.c \
  keyd-function.c \
  distinguisher.c \
  attack.c \
  main.c

OBJS := $(SRCS:.c=.o)
BIN := aes

.PHONY: all clean run run-random rebuild help

all: $(BIN)

$(BIN): $(OBJS)
    $(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
    $(CC) $(CFLAGS) -c $< -o $@

# Convenience target: rebuild everything
rebuild: clean all

# Run examples
run: $(BIN)
    ./$(BIN)

run-random: $(BIN)
    ./$(BIN) random

# Clean build artifacts
clean:
    rm -f $(OBJS) $(BIN)

# Show available targets
help:
    @echo "Targets:"
    @echo "  all          - Build $(BIN) (default)"
    @echo "  run          - Run ./$(BIN)"
    @echo "  run-random   - Run ./$(BIN) random"
    @echo "  rebuild      - Clean and build"
    @echo "  clean        - Remove objects and binary"
