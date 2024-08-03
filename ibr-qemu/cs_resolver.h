#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* 利用Capstone解析指令，实现多平台兼容  
*/

enum arch_t {
	arm32,
	aarch64,
	x86_64,
	unknown,
};

extern int current_arch;

/* x86_64 helpers */
bool support_arch(const char *arch);

bool capstone_is_indirect_branch(uint8_t *insn_data, size_t insn_size);

bool capstone_get_reg_name(uint8_t *insn, size_t insn_len, char *reg);