CC := clang
OBJDUMP := objdump

COMMON_FILES = $(wildcard common/*.c)
COMMON_SRC = $(notdir $(COMMON_FILES))
COMMON_TESTS = $(patsubst %.c, %, $(COMMON_SRC))

ARM_SRC = $(wildcard arm/*.c)

TARGET := ../../out/x86_64

all: $(COMMON_TESTS) $(TARGET)

$(TARGET):
	mkdir -p $(TARGET)

%: common/%.c $(TARGET)
	$(CC) -o $(TARGET)/$@.elf $<
	$(OBJDUMP) -S $(TARGET)/$@.elf > $(TARGET)/$@.list