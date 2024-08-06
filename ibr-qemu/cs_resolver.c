#include "cs_resolver.h"

#include "debug.h"
#include "arch/arch.h"

#include <assert.h>
#include <glib.h>
#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdlib.h>

/* 基于Capstone来实现
https://github.com/capstone-engine/capstone/blob/5ba4ca4ba6b9ba7edb41243a036f973cb056d143/include/capstone/capstone.h#L314C2-L314C24
*/

// 和qemu arch名一致
const char *sup_arch[unknown + 1] = {
	[arm] = "arm",
	[aarch64] = "aarch64",
	"x86_64",
	"mips",
	"mipsel",
	"mips64",
	"mips64el",
	"ppc64",
	"ppc64le",
	"riscv32",
	"riscv64",
	[unknown]="unknown",
};

int current_arch = unknown;

static csh handle = 0;

static void init_capstone();
static int capstone_get_insn_reg(cs_insn *insn);

bool support_arch(const char *arch)
{
	// DEBUG_LOG("Current Arch: %s\n", arch);
	current_arch = unknown;
	for (int i = 0; i < unknown; i++) {
		if (strcmp(arch, sup_arch[i]) == 0) {
			current_arch = i;
		}
	}
	if (current_arch == unknown) {
		return false;
	}
	init_capstone();
	return true;
}

/* 通过指令group来判断间接跳转  
CS_GRP_JUMP:
CS_GRP_CALL:
CS_GRP_BRANCH_RELATIVE: cmp也包含，地址可以是offset和寄存器
*/
bool capstone_is_indirect_branch(uint8_t *insn_data, size_t insn_size)
{
	cs_insn *insn;
	size_t count = cs_disasm(handle, insn_data, insn_size, 0, 0, &insn);
	bool is_ib = false;
	if (count > 0) {
		cs_insn *ins = &insn[0];
		printf("ins->id: %d\n", ins->id);
		if (current_arch == x86_64) {
			is_ib = x86_64_is_indirect_branch(ins);
		}
		else if (current_arch == aarch64) {
			is_ib = aarch64_is_indirect_branch(ins);
		} 
		else if (current_arch == arm) {
			is_ib = arm_is_indirect_branch(ins);
		}
		else if (current_arch == mips) {
			is_ib = mips_is_indirect_branch(ins);
		}
		else if (current_arch == mipsel) {
			is_ib = mipsel_is_indirect_branch(ins);
		}
		else if (current_arch == mips64) {
			is_ib = mips64_is_indirect_branch(ins);
		}
		else if (current_arch == mips64el) {
			is_ib = mips64el_is_indirect_branch(ins);
		}
		else if (current_arch == ppc64) {
			is_ib = ppc64_is_indirect_branch(ins);
		}
		else if (current_arch == ppc64le) {
			is_ib = ppc64le_is_indirect_branch(ins);
		}
		else if (current_arch == riscv32) {
			// DEBUG_LOG("WARN: is_ib for arch %s is not implemented\n", sup_arch[current_arch]);
		}
		else if (current_arch == riscv64) {
			// DEBUG_LOG("WARN: is_ib for arch %s is not implemented\n", sup_arch[current_arch]);
		}
		else {
			// DEBUG_LOG("WARN: is_ib for arch %s is not implemented\n", sup_arch[current_arch]);
		}
	}
	cs_free(insn, count);
	return is_ib;
}

bool capstone_get_reg_name(uint8_t *insn, size_t insn_len, char *reg_name)
{
	cs_insn *insn_cs;
	size_t count = cs_disasm(handle, insn, insn_len, 0, 0, &insn_cs);
	uint64_t target = 0;
	if (count > 0) {
		cs_insn *ins = &insn_cs[0];
		int reg = capstone_get_insn_reg(ins);
		if (reg >= 0) {
			strcpy(reg_name, cs_reg_name(handle, reg));
		}
		cs_free(insn_cs, count);
		return true;
	}
	cs_free(insn_cs, count);
	return false;
}

static void init_capstone()
{
	int cs_conf[][2] = {
		[arm] = {CS_ARCH_ARM, CS_MODE_ARM},
		[aarch64] = {CS_ARCH_AARCH64, CS_MODE_ARM},
		[x86_64] = {CS_ARCH_X86, CS_MODE_64},
		[mips] = {CS_ARCH_MIPS, CS_MODE_MIPS32  | CS_MODE_BIG_ENDIAN},
		[mipsel] = {CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN},
		[mips64] = {CS_ARCH_MIPS, CS_MODE_MIPS64  | CS_MODE_BIG_ENDIAN},
		[mips64el] = {CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN},
		[ppc64] = {CS_ARCH_PPC, CS_MODE_64 | CS_MODE_LITTLE_ENDIAN},
		[ppc64le] = {CS_ARCH_PPC, CS_MODE_64 | CS_MODE_LITTLE_ENDIAN},
		// [riscv32] = {CS_ARCH_RISCV, CS_MODE_RISCV32},
		// [riscv64] = {CS_ARCH_RISCV, CS_MODE_RISCV64},
		[unknown] = {-1, -1},
	};

	assert(current_arch < sizeof(cs_conf) / (sizeof(int) *2));
	
	if (cs_open(cs_conf[current_arch][0], cs_conf[current_arch][1], &handle) != CS_ERR_OK) {
		FATAL_ERR("Failed to inital Capstone for arch: %s\n", sup_arch[current_arch]);
	}

	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON)) {
		FATAL_ERR("Failed to set Capstone detail insn for arch: %s\n", sup_arch[current_arch]);
	}
}

static int capstone_get_insn_reg(cs_insn *insn)
{
	g_assert(insn->detail);
	if (current_arch == x86_64) {
		for (size_t i = 0; i < insn->detail->x86.op_count; i++) {
			cs_x86_op *op = &insn->detail->x86.operands[i];
			if (op->type == X86_OP_REG) {
				return op->reg;
			}
		}
	} else if (current_arch == aarch64) {
		for (size_t i = 0; i < insn->detail->aarch64.op_count; i++) {
			cs_aarch64_op *op = &insn->detail->aarch64.operands[i];
			if (op->type == AARCH64_OP_REG) {
				return op->reg;
			}
		}
	} else if (current_arch == arm) {
		for (size_t i = 0; i < insn->detail->arm.op_count; i++) {
			cs_arm_op *op = &insn->detail->arm.operands[i];
			if (op->type == ARM_OP_REG) {
				return op->reg;
			}
		}
	} else if (current_arch == mips || current_arch == mipsel || current_arch == mips64 || current_arch == mips64el) {
		for (size_t i = 0; i < insn->detail->mips.op_count; i++) {
			cs_mips_op *op = &insn->detail->mips.operands[i];
			if (op->type == MIPS_OP_REG) {
				return op->reg;
			}
		}
	} else if (current_arch == ppc64 || current_arch == ppc64le) {
		for (size_t i = 0; i < insn->detail->ppc.op_count; i++) {
			cs_ppc_op *op = &insn->detail->ppc.operands[i];
			if (op->type == PPC_OP_REG) {
				return op->reg;
			}
		}
	} else {
		DEBUG_LOG("WARN: get reg for arch %s is not implemented\n", sup_arch[current_arch]);
	}

	return -1;
}