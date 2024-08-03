

/*
测试不同架构的 indirect branch是否实现正确  
*/

struct insn_test {
	char insn[16];
	char disa[16];
	int ground_truth; // 1，间接跳转
};

// aarch64
const struct insn_test aarch64_test = {
	{"\x40\x00\x3f\xd6", "blr x2", 1},
	{"\x58\x01\x00\x94", "bl #560", 0},
	{"\xc1\x03\x00\xb4", "cbz x1, #0x78", 0},
};