#include <capstone/ppc.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>

#include <capstone/capstone.h>

// https://shell-storm.org/online/Online-Assembler-and-Disassembler/

// #define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"
// #define CODE "\xff\xd5"
// #define CODE "\xe8\xa7\xfc\xff\xff"

// aarch64
// #define CODE "\x40\x00\x3f\xd6" // blr x2
// #define CODE "\x58\x01\x00\x94" // bl #560
// #define CODE "\xc1\x03\x00\xb4" // cbz x1, #0x78
// #define CODE "\x09\xf8\x20\x03\x00\x00\x00\x00" // mipsel jalr $t9 
// #define CODE "\x03\x20\xf8\x09"
#define CODE "\x7d\x89\x03\xa6" // mctrl r12

csh handle;

static void dump_ins_op_arm64(cs_insn *insn)
{
	cs_arm64_op *cs_op;
	printf("arm64 op count: %d\n", insn->detail->arm64.op_count);
	for (size_t i = 0; i < insn->detail->arm64.op_count; i++) {
		cs_op = &(insn->detail->arm64.operands[i]);
		printf("op type: %d\n", cs_op->type);
		if (cs_op->type == ARM64_OP_REG) {
			printf("reg: %s %d\n", cs_reg_name(handle, cs_op->reg), cs_op->reg);
		}
		if (cs_op->type == ARM64_OP_IMM) {
			printf("imm: 0x%"PRIx64"\n", cs_op->imm);
		}
	}
}

static void dump_x86_op(cs_insn *insn)
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

static void dump_mips_op(cs_insn *insn)
{
	cs_mips_op *cs_op;
	printf("mips op count: %d\n", insn->detail->mips.op_count);
	for (size_t i = 0; i < insn->detail->mips.op_count; i++) {
		cs_op = &(insn->detail->mips.operands[i]);
		printf("op type: %d\n", cs_op->type);
		if (cs_op->type == MIPS_OP_REG) {
			printf("reg: %s %d\n", cs_reg_name(handle, cs_op->reg), cs_op->reg);
		}
		if (cs_op->type == MIPS_OP_IMM) {
			printf("imm: 0x%"PRIx64"\n", cs_op->imm);
		}
	}
}

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
	
	int is_ib = 0;
	for (size_t i = 0;i < ins->detail->groups_count;i++) {
		if (ins->detail->groups[i] == CS_GRP_JUMP || ins->detail->groups[i] == CS_GRP_BRANCH_RELATIVE) {
			is_ib = true;
			// dump_ins_op_arm64(ins);
		}
	}

	// PPC_OP_REG

	if (is_call) {
		printf("----------------------\n");
		printf("is call: %d\n", is_call);
		dump_mips_op(ins);
		printf("----------------------\n");
	}

	if (is_ib) {
		printf("----------------------\n");
		printf("is branch: %d\n", is_ib);
		dump_mips_op(ins);
		printf("----------------------\n");
	}

	// if (is_call) {
	// 	for (size_t i = 0;i < ins->detail->regs_read_count;i++) {
	// 		printf("reg: %d\n", ins->detail->regs_read[i]);
	// 		if (ins->detail->regs_read[i] == X86_REG_RIP) {
	// 			return true;
	// 		}
	// 	}
	// }
	
	return false;
}

int main(void)
{
	cs_insn *insn;
	size_t count;

	// CS_ARCH_X86, CS_MODE_64
	// 
	int arch = CS_ARCH_PPC;
	int mode = CS_MODE_64 | CS_MODE_BIG_ENDIAN;

	if (cs_open(arch, mode, &handle) != CS_ERR_OK)
		return -1;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	// cs_regs regs_read, regs_write;
	// uint8_t read_count, write_count, i;

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