#pragma once

#include <capstone/capstone.h>
#include <capstone/mips.h>
#include <stddef.h>
#include <stdbool.h>
#include "../debug.h"


/*
目前capstone不支持riscv
*/


static bool riscv32_is_indirect_branch(cs_insn *insn)
{
	return false;
}

static bool riscv64_is_indirect_branch(cs_insn *insn)
{
	return false;
}