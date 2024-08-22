#pragma once

#include <capstone/capstone.h>
#include <capstone/mips.h>
#include <stddef.h>
#include <stdbool.h>
#include "../debug.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static const char * reg_name_maps[] = {
	[0] = "r0",
	[1] = "r1",
	[2] = "r2",
	[3] = "r3",
	[4] = "r4",
	[5] = "r5",
	[6] = "r6",
	[7] = "r7",
	[8] = "r8",
	[9] = "r9",
	[10] = "r10",
	[11] = "r11",
	[12] = "r12",
	[13] = "r13",
	[14] = "r14",
	[15] = "r15",
	[16] = "r16",
	[17] = "r17",
	[18] = "r18",
	[19] = "r19",
	[20] = "r20",
	[21] = "r21",
	[22] = "r22",
	[23] = "r23",
	[24] = "r24",
	[25] = "r25",
	[26] = "r26",
	[27] = "r27",
	[28] = "r28",
	[29] = "r29",
	[30] = "r30",
	[31] = "r31",
	[32] = "(null)",
	[33] = "lo",
	[34] = "hi",
	[35] = "(null)",
	[36] = "(null)",
	[37] = "pc",
};


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

/*
https://github.com/capstone-engine/capstone/blob/next/arch/Mips/MipsMapping.c#L18
由于capstone的mips寄存器名称和qemu/gdb的不一致，所以需要转换
https://github.com/capstone-engine/capstone/blob/next/arch/Mips/MipsMapping.c#L202
*/
static const char * mips_get_reg_name(unsigned int reg_id)
{	
	// mips r0 = zero
	reg_id -= MIPS_REG_0;
	if (reg_id >= ARRAY_SIZE(reg_name_maps)) {
		return NULL;
	}
	return reg_name_maps[reg_id];
}