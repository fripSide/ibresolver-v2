
OBJDUMP := objdump

COMMON_FILES = $(wildcard common/*.c)
COMMON_SRC = $(notdir $(COMMON_FILES))
COMMON_TESTS = $(patsubst %.c, %, $(COMMON_SRC))

ARM_SRC = $(wildcard arm/*.c)

TARGET := x86_64

all: $(COMMON_TESTS)

$(TARGET):
	mkdir -p $(TARGET)

%: common/%.c $(TARGET)
	$(CC) -o $(TARGET)/$@.elf $<
	$(OBJDUMP) -S $(TARGET)/$@.elf > $(TARGET)/$@.list


arm_test:
	$(CC) -o arm_test arm_test.c
	$(OBJDUMP) -S arm_test > arm_test.list