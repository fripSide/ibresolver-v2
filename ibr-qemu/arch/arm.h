#pragma once

#include <capstone/capstone.h>
#include <stddef.h>
#include <stdbool.h>
#include "../debug.h"

static bool arm_is_indirect_branch(cs_insn *insn)
{
	/* all jump instructions (conditional+direct+indirect jumps)
	* jmp, cmp and jmp b/br/bl/blr/cbnz/cbz
	*/
	bool is_jump = false;
	for (size_t i = 0; i < insn->detail->groups_count; i++) {
		if (insn->detail->groups[i] == CS_GRP_JUMP || insn->detail->groups[i] == CS_GRP_BRANCH_RELATIVE) {
			is_jump = true;
		}
	}

	/* indirect jump，只有一个操作数就是寄存器
	*/
	if (is_jump) {
		if (insn->detail->arm.op_count == 1) {
			cs_arm_op *op = &insn->detail->arm.operands[0];
			if (op->type == ARM_OP_REG) {
				// 忽略：bl/blx lr
				// DEBUG_LOG("is jump: %d %d reg: %d\n", op->type, ARM_REG_LR, op->reg);
				return op->reg != ARM_REG_LR;
			}
		}
	}
	return false;
}