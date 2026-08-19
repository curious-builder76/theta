
CC=gcc

CFLAGS= -Wall -Wextra

DEBUG_FLAGS= -ggdb -fsanitize=address,undefined

INCLUDE_LIBS= -Lsphlib 

INCLUDE_DIRS= -Isphlib

LIBS= -lsph

TARGET= -o theta

FILES=theta.c


OPTIMIZE_FLAGS= -O2 -march=native -fomit-frame-pointer


.PHONY: build
build:
	$(CC) $(FILES)  $(CFLAGS) $(OPTIMIZE_FLAGS) $(INCLUDE_DIRS)  $(INCLUDE_LIBS) $(LIBS) $(TARGET)

.PHONY: debug
debug:
	$(CC) $(FILES) $(CFLAGS) $(DEBUG_FLAGS) $(INCLUDE_DIRS)  $(INCLUDE_LIBS) $(LIBS)  $(TARGET)

