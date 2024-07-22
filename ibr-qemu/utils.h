#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

bool support_arch(const char *arch);

bool is_indirect_branch(uint8_t *insn_data, size_t insn_size);