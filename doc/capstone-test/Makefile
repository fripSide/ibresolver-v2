# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME = capstone
CFLAGS = -I../../qemu/capstone/include
# 使用qemu的capstone
LDFLAGS = -lcapstone -Wl,-rpath=./../../qemu/capstone 


.PHONY: test1

test1.exe: test1.o
	${CC} $< -O3 -Wall -o $@ $(LDFLAGS)
	./test1.exe

%.o: %.c
	${CC} $(CFLAGS) -g -c $< -o $@