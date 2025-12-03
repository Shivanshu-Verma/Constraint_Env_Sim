CC ?= gcc
BUILD_DIR := build
WOLFSSL_ROOT := ../boot
WOLFSSL_INC := include $(WOLFSSL_ROOT) $(WOLFSSL_ROOT)/wolfssl $(WOLFSSL_ROOT)/wolfssl/wolfcrypt \
			   $(WOLFSSL_ROOT)/wolfcrypt/src

CFLAGS += -I. $(addprefix -I,$(WOLFSSL_INC)) -DWOLFSSL_USER_SETTINGS -O2 -g \
          -Wall -Wextra -Wno-unused-parameter -Wno-unused-function
LDFLAGS +=
LDLIBS += -lm -lpthread

WOLFSSL_SRCS := $(wildcard $(WOLFSSL_ROOT)/src/*.c) \
                $(wildcard $(WOLFSSL_ROOT)/wolfcrypt/src/*.c)
WOLFSSL_OBJS := $(patsubst $(WOLFSSL_ROOT)/%,$(BUILD_DIR)/%,$(WOLFSSL_SRCS:.c=.o))
SERVER_OBJ := $(BUILD_DIR)/server.o

all: server

server: $(SERVER_OBJ) $(WOLFSSL_OBJS)
	$(CC) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/server.o: server.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(WOLFSSL_ROOT)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) server

.PHONY: all clean
