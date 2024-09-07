C_FLAGS = `pkg-config --cflags glib-2.0` -fsanitize=address
LDFLAGS = `pkg-config --libs glib-2.0` -static-libasan

test.exe: test.c
	gcc -o test.exe test.c $(C_FLAGS) $(LDFLAGS)

run: test.exe
# export ASAN_OPTIONS=verify_asan_link_order=0
	memusage ./test.exe

clean:
	rm -f test.exe