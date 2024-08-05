CC = clang
CXX = clang++

CXXFLAGS = -fPIC -std=c++17
CFLAGS = -fPIC

# MAKEDEPEND = makedepend -f- $(CPPFLAGS) $< | sed -n 's,^[^\#][^:]*: *\(..*\),$@: \1\n\1:,p' > $*.d

LIB_CAPSTONE = capstone

QEMU_DIR = $(shell pwd)/../qemu

QEMU_PLUGIN_H = $(QEMU_DIR)/include/qemu/

INCLUDES = -I$(shell pwd)/ -I$(QEMU_PLUGIN_H) `pkg-config --cflags glib-2.0`

LDFLAGS = -shared -lstdc++ `pkg-config --libs glib-2.0` -l$(LIB_CAPSTONE)

# 头文件修改也重新编辑
ARCH_FILES = $(wildcard arch/*.h)

COMMON_OBJS = utils.o cs_resolver.o

all: libibr1.so libibr2.so
.PHONY: clean

%.o: %.c $(ARCH_FILES)
	$(CC) -c $(CFLAGS) $(INCLUDES) $(DEFINES) $< -o $@

libibr1.so: plugin1.o $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^


libibr2.so: plugin2.o $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

unit_test:
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -o unit_test test.c

clean:
	rm -f *.o *.so

# include $(wildcard $(PLUGIN2_SRC:.o=.d))