#pragma once

#include <capstone/capstone.h>
#include <stddef.h>
#include <stdbool.h>

static bool aarch64_is_indirect_branch(cs_insn *insn)
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
		if (insn->detail->arm64.op_count == 1) {
			cs_arm64_op *op = &insn->detail->arm64.operands[0];
			if (op->type == ARM64_OP_REG) {
				return true;
			}
		}
	}
	return false;
}