.PHONY: build clean

CC ?= gcc
CFLAGS := -shared -fPIC -Wall -Wextra -Werror -O2
LDFLAGS := -ldl -lpthread
TARGET := libfence_fs.so
SRC := libfence_fs.c

build: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
