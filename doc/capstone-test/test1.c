#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>

#include <capstone/capstone.h>

// #define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"
// #define CODE "\xff\xd5"
// #define CODE "\xe8\xa7\xfc\xff\xff"

// aarch64
#define CODE "\x40\x00\x3f\xd6" // blr x2
// #define CODE "\x58\x01\x00\x94" // bl #560
// #define CODE "\xc1\x03\x00\xb4" // cbz x1, #0x78

csh handle;

bool capstone_is_ib(cs_insn *ins)
{
	if (ins == NULL || ins->detail == NULL) {
		return false;
	}
	bool is_call = false;
	for (size_t i = 0;i < ins->detail->groups_count;i++) {
		if (ins->detail->groups[i] == CS_GRP_CALL) {
			is_call = true;
		}
	}
	printf("is call: %d\n", is_call);

	int is_ib = 0;
	for (size_t i = 0;i < ins->detail->groups_count;i++) {
		// if (ins->detail->groups[i] == CS_GRP_JUMP) {
		// 	is_call = true;
		// }
		//  || ins->detail->groups[i] == CS_GRP_JUMP
		if (ins->detail->groups[i] == CS_GRP_BRANCH_RELATIVE) {
			is_ib = true;
			for (size_t i = 0; i < ins->detail->arm64.op_count; i++) {
				cs_arm64_op *op = &ins->detail->arm64.operands[i];
				if (op->type == ARM64_OP_REG) {
					char reg_num[32];
					printf("find reg: %d %s cnt: %d\n", op->reg, cs_reg_name(handle, op->reg), ins->detail->arm64.op_count);
				}
			}
			return true;
		}
	}
	if (is_call) {
		for (size_t i = 0;i < ins->detail->regs_read_count;i++) {
			printf("reg: %d\n", ins->detail->regs_read[i]);
			if (ins->detail->regs_read[i] == X86_REG_RIP) {
				return true;
			}
		}
	}
	
	return false;
}

bool capstone_is_indirect_branch(uint8_t *insn_data, size_t insn_size)
{
	cs_insn *insn;
	size_t count = cs_disasm(handle, insn_data, insn_size, 0, 0, &insn);

	if (count > 0) {
		cs_insn *ins = &insn[0];
		printf("%p\n", ins->detail);
		for (size_t i = 0;i < ins->detail->groups_count; i++) {
			if (ins->detail->groups[i] == CS_GRP_CALL && ins->detail->regs_read_count > 0) {
				cs_free(insn, count);
				return true;
			}
		}
		cs_free(insn, count);
	}
	return false;
}

void dump_x86_op(cs_insn *insn)
{
	cs_x86_op *cs_op;
	printf("x86 op count: %d\n", insn->detail->x86.op_count);
	for (size_t i = 0; i < insn->detail->x86.op_count; i++) {
		cs_op = &(insn->detail->x86.operands[i]);
		printf("op type: %d\n", cs_op->type);
		if (cs_op->type == X86_OP_REG) {
			printf("reg: %s %d\n", cs_reg_name(handle, cs_op->reg), cs_op->reg);
		}
		if (cs_op->type == X86_OP_IMM) {
			printf("imm: 0x%"PRIx64"\n", cs_op->imm);
		}
	}
}

int main(void)
{
	cs_insn *insn;
	size_t count;

	// CS_ARCH_X86, CS_MODE_64
	int arch = CS_ARCH_ARM64;
	int mode = CS_MODE_ARM;

	if (cs_open(arch, mode, &handle) != CS_ERR_OK)
		return -1;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	// cs_regs regs_read, regs_write;
	// uint8_t read_count, write_count, i;

	// printf("capstone is indirect branch: %d\n", capstone_is_indirect_branch(CODE, sizeof(CODE)-1));

	count = cs_disasm(handle, CODE, sizeof(CODE)-1, 0x1000, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
			printf("reg num: %d\n", insn[j].detail->regs_read_count);
			printf("is indirect branch: %d\n", capstone_is_ib(&insn[j]));

			// dump_x86_op(&insn[j]);
		}
		cs_free(insn, count);
	} else {
		printf("ERROR: Failed to disassemble given code!\n");
	}

	cs_close(&handle);

    return 0;
}