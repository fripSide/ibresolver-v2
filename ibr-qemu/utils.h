#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

bool is_indirect_branch(uint8_t *insn_data, size_t insn_size);

bool covert_vaddr_to_offset(uint64_t inst_vaddr, uint64_t *offset, char *image_name);