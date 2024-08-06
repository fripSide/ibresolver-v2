# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME = capstone
CFLAGS = -I../../capstone/include
LDFLAGS = -L../../capstone -lcapstone -Wl,-rpath=./../../capstone 


.PHONY: test1

test1: test1.o
	${CC} $< -O3 -Wall -o $@ $(LDFLAGS)
	./test1

%.o: %.c
	${CC} $(CFLAGS) -g -c $< -o $@