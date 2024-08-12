#pragma once

#include <capstone/capstone.h>
#include <capstone/mips.h>
#include <stddef.h>
#include <stdbool.h>
#include "../debug.h"


static bool riscv_is_indirect_branch(cs_insn *insn)
{
	bool is_call = false;
	// CALL还包括：scv/bl。svc, blx, svceq, scvpl, blge等
	for (size_t i = 0;i < insn->detail->groups_count;i++) {
		if (insn->detail->groups[i] == CS_GRP_CALL) {
			is_call = true;
		}
	}
	// call寄存器
	if (is_call) {
		// DEBUG_LOG("riscv_is_indirect_branch: %d %d %d %s %s\n", is_call, insn->id, insn->detail->riscv.op_count,
		// 	insn->mnemonic, insn->op_str);

		if (insn->detail->riscv.op_count == 1) {
			cs_riscv_op *op = &insn->detail->riscv.operands[0];
			if (op->type == RISCV_OP_REG) {
				return true;
			}
		}
	}
	return false;
}
