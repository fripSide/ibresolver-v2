#pragma once

#include <capstone/capstone.h>
#include <capstone/mips.h>
#include <stddef.h>
#include <stdbool.h>
#include "../debug.h"


static bool mips_is_indirect_branch(cs_insn *insn)
{
	// call: jal instruction
	bool is_call = false;
	for (size_t i = 0; i < insn->detail->groups_count; i++) {
		if (insn->detail->groups[i] == CS_GRP_CALL) {
			is_call = true;
		}
	}

	if (is_call) {
		if (insn->detail->mips.op_count == 1) {
			cs_mips_op *op = &insn->detail->mips.operands[0];
			// DEBUG_LOG("op_count: %d op-type: %d\n", insn->detail->mips.op_count, op->type);
			if (op->type == MIPS_OP_REG) {
				// return op->reg != ARM_REG_LR;
				return true;
			}
		}
	}
	return false;
}


static bool mipsel_is_indirect_branch(cs_insn *insn)
{

	return mips_is_indirect_branch(insn);
}


static bool mips64_is_indirect_branch(cs_insn *insn)
{

	return mips_is_indirect_branch(insn);
}

static bool mips64el_is_indirect_branch(cs_insn *insn)
{
	return mips_is_indirect_branch(insn);
}