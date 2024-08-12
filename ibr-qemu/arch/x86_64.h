#pragma once

#include <capstone/capstone.h>
#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "../debug.h"

/* call指令，参数有寄存器
*/
static bool x86_64_is_indirect_branch(cs_insn *insn)
{
	bool is_call = false;
	ASSERT(insn && insn->detail);
	for (size_t i = 0; i < insn->detail->groups_count;i++) {
		if (insn->detail->groups[i] == CS_GRP_CALL) {
			is_call = true;
			break;
		}
	}
	if (is_call) {
		
		for (size_t i = 0; i < insn->detail->x86.op_count; i++) {
			cs_x86_op *op = &insn->detail->x86.operands[i];
			if (op->type == X86_OP_REG) {
				return true;
			}
		}
	}
	return false;
}