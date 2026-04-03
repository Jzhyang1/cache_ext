
GCC ?= gcc
CFLAGS = -O2 -fsanitize=address -g -Wall

all: linscansparse.out rephit.out

%.out: %.c
	$(GCC) $(CFLAGS) $< -o $@
