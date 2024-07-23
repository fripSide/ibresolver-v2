#include "cs_resolver.h"

#include "debug.h"
#include <glib.h>

#include <capstone/capstone.h>

/* 基于Capstone来实现
https://github.com/capstone-engine/capstone/blob/5ba4ca4ba6b9ba7edb41243a036f973cb056d143/include/capstone/capstone.h#L314C2-L314C24
*/

int current_arch = unknown;

static csh handle = 0;

static void init_capstone();
static int capstone_get_insn_reg(cs_insn *insn);
static bool capstone_insn_is_call(cs_insn *insn);

bool support_arch(const char *arch)
{
	// DEBUG_LOG("Current Arch: %s\n", arch);
	if (strcmp(arch, "arm") == 0) {
		current_arch = arm32;
	} else if (strcmp(arch, "aarch64") == 0) {
		current_arch = aarch64;
	} else if (strcmp(arch, "x86_64") == 0) {
		current_arch = x86_64;
	}
	init_capstone();
	return current_arch != unknown;
}

bool capstone_is_indirect_branch(uint8_t *insn_data, size_t insn_size)
{
	cs_insn *insn;
	size_t count = cs_disasm(handle, insn_data, insn_size, 0, 0, &insn);
	bool is_ib = false;
	if (count > 0) {
		cs_insn *ins = &insn[0];

		// call的操作数是寄存器
		if (capstone_insn_is_call(ins)) {
			is_ib = capstone_get_insn_reg(ins) > 0;
		}
		
	}
	cs_free(insn, count);
	return is_ib;
}

bool capstone_call_get_reg_name(uint8_t *insn, size_t insn_len, char *reg_name)
{
	cs_insn *insn_cs;
	size_t count = cs_disasm(handle, insn, insn_len, 0, 0, &insn_cs);
	uint64_t target = 0;
	if (count > 0) {
		cs_insn *ins = &insn_cs[0];
		if (capstone_insn_is_call(ins)) {
			int reg = capstone_get_insn_reg(ins);
			if (reg >= 0) {
				strcpy(reg_name, cs_reg_name(handle, reg));
			}
			cs_free(insn_cs, count);
			return true;
		}
	}
	cs_free(insn_cs, count);
	return false;
}

static void init_capstone()
{
	int cs_conf[][2] = {
		[arm32] = {CS_ARCH_ARM, CS_MODE_ARM},
		[aarch64] = {CS_ARCH_ARM64, CS_MODE_ARM},
		[x86_64] = {CS_ARCH_X86, CS_MODE_64},
		[unknown] = {-1, -1},
	};
	
	if (cs_open(cs_conf[current_arch][0], cs_conf[current_arch][1], &handle) != CS_ERR_OK) {
		FATAL_ERR("Failed to open Capstone\n");
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
}

static bool capstone_insn_is_call(cs_insn *insn)
{
	for (size_t i = 0; i < insn->detail->groups_count;i++) {
		if (insn->detail->groups[i] == CS_GRP_CALL) {
			return true;
		}
	}
	return false;
}

static int capstone_get_insn_reg(cs_insn *insn)
{
	g_assert(insn->detail);
	if (current_arch == x86_64) {
		// 
		for (size_t i = 0; i < insn->detail->x86.op_count; i++) {
			cs_x86_op *op = &insn->detail->x86.operands[i];
			if (op->type == X86_OP_REG) {
				return op->reg;
			}
		}
	}
	return -1;
}