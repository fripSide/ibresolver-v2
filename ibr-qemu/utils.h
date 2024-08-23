#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

bool is_indirect_branch(uint8_t *insn_data, size_t insn_size);

bool covert_vaddr_to_offset(uint64_t inst_vaddr, uint64_t *offset, char *image_name);

void copy_reg_value(uint64_t *dest_val, uint8_t *reg_val, int reg_sz, bool is_big_endian);