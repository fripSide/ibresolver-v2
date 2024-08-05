
OBJDUMP ?= objdump

COMMON_FILES = $(wildcard ../common/*.c)

# 当前目录的架构专用测试
ARCH_FILES = $(wildcard *.c)

# 文件名（不包括后缀）
COMMON_TESTS = $(patsubst %.c, %, $(notdir $(COMMON_FILES)))
ARCH_TESTS = $(patsubst %.c, %, $(ARCH_FILES))

ALL_TESTS = $(COMMON_TESTS) $(ARCH_TESTS)

TARGET := ../../out/$(ARCH)

all: $(ALL_TESTS) $(TARGET)

# 匹配common目录的c文件
VPATH = ../common

$(TARGET):
	mkdir -p $(TARGET)

%: %.c $(TARGET)
	$(CC) -o $(TARGET)/$@.elf $<
	$(OBJDUMP) -S $(TARGET)/$@.elf > $(TARGET)/$@.list

clean:
	rm -rf $(TARGET)