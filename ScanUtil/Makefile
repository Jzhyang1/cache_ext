
GCC ?= gcc
CFLAGS = -O2 -fsanitize=address -g -Wall

all: linscansparse.out

linscansparse.out: linscansparse.c
	$(GCC) $(CFLAGS) $< -o $@