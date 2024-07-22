#include <stdio.h>

typedef int (*OP)(int, int);

int add(int x, int y) {
	return x + y;
}

int sub(int x, int y) {
	return x - y;
}

int mul(int x, int y) {
	return x * y;
}

int div(int x, int y) {
	return x / y;
}

int main(int argc, char const *argv[]) {
	int x = 5, y = 6;
	OP operation = NULL;
	switch (argc % 4) {
		case 0:
			operation = add;
			break;
		case 1:
			operation = sub;
			break;
		case 2:
			operation = mul;
			break;
		case 3:
			operation = div;
			break;
		default:
			break;
	}
	if (operation) {
		printf("argc: %d %p %d\n", argc, operation, operation(x, y));
	}
	return 0;
}
/*
*/