export CROSS_TARGET=arm64-unknown-elf

# CC := xcross cc 
# OBJDUMP := xcross objdump
CC := aarch64-linux-gnu-gcc
OBJDUMP := aarch64-linux-gnu-objdump

COMMON_FILES = $(wildcard ../common/*.c)

# 当前目录的架构专用测试
ARCH_FILES = $(wildcard *.c)

# 文件名（不包括后缀）
COMMON_TESTS = $(patsubst %.c, %, $(notdir $(COMMON_FILES)))
ARCH_TESTS = $(patsubst %.c, %, $(ARCH_FILES))

ALL_TESTS = $(COMMON_TESTS) $(ARCH_TESTS)

TARGET := ../../out/aarch64

all: $(ALL_TESTS) $(TARGET)
.PHONY: clean

# 匹配common目录的c文件
VPATH = ../common

$(TARGET):
	mkdir -p $(TARGET)

%: %.c $(TARGET)
	$(CC) -o $(TARGET)/$@.elf $<
	$(OBJDUMP) -S $(TARGET)/$@.elf > $(TARGET)/$@.list

clean:
	rm -rf $(TARGET)