#pragma once

#include <capstone/capstone.h>
#include <capstone/mips.h>
#include <capstone/ppc.h>
#include <stddef.h>
#include <stdbool.h>
#include "../debug.h"


static bool ppc64_is_indirect_branch(cs_insn *insn)
{
	// Powever PC Indirect Function Call: 
	// mtlr r0 
	// blrl
	DEBUG_LOG("mtlr: %d %d %lx %s\n", PPC_INS_MTLR, insn->id, insn->alias_id, insn->op_str);
	if (insn->id == PPC_INS_MTLR) {
		if (insn->detail->ppc.op_count == 1) {
			cs_ppc_op *op = &insn->detail->ppc.operands[0];
			if (op->type == PPC_OP_REG) {
				return true;
			}
		}
	}
	return false;
}

static bool ppc64le_is_indirect_branch(cs_insn *insn)
{
	return ppc64_is_indirect_branch(insn);
}