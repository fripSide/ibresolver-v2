#include <stdio.h>
#include <stdlib.h>

typedef int (*func_t)(int a, int b);

int add(int a, int b) {
	return a + b;
}

int sub(int a, int b) {
	return a - b;
}

int mul(int a, int b) {
	return a * b;
}

func_t vector_tbl[3] = {
	add,
	sub,
	mul
};

int main(int argc, const char *argv[]) {
	int a = 10;
	int b = 5;
	int op = 0;

	if (argc > 1) {
		op = atoi(argv[1]);
	}

	if (op < 0 || op >= 3) {
		printf("Invalid operation\n");
		return -1;
	}

	printf("Result: %d\n", vector_tbl[op](a, b));

	return 0;
}

