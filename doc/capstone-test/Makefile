# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME = capstone


.PHONY: test1

test1: test1.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@
	./test1

%.o: %.c
	${CC} -g -c $< -o $@