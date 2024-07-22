
OBJDUMP := objdump

FILES = $(wildcard cases/*.c)
SRC = $(notdir $(FILES))
TESTS = $(patsubst %.c, %, $(SRC))

TARGET := x86_64

all: $(TESTS)

$(TARGET):
	mkdir -p $(TARGET)

%: cases/%.c $(TARGET)
	$(CC) -o $(TARGET)/$@.elf $<
	$(OBJDUMP) -S $(TARGET)/$@.elf > $(TARGET)/$@.list
