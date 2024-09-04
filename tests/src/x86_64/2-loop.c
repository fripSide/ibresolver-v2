#include <stdio.h>

int add(int a, int b) {
	return a + b;
}

int sub(int a, int b) {
	return a - b;
}

typedef int (*func_t)(int, int);

int main() {
	func_t func[2] = {add, sub};
	for (int i = 0; i < 10; i++) {
		printf("loop %d -> %d\n", i, func[i % 2](i * i + 1, i));
	}
	return 0;
}