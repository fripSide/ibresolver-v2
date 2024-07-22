#include "utils.h"

#include <stdint.h>
#include <string.h>
#include "debug.h"


// convert to capstone arch
enum arch_t {
	arm32,
	aarch64,
	x86_64,
	unknown,
};

static int current_arch = unknown;

#ifdef USE_BINARY_NINJA

#else

bool support_arch(const char *arch)
{
	// DEBUG_LOG("Current Arch: %s\n", arch);
	if (strcmp(arch, "arm") == 0) {
		current_arch = arm32;
		return true;
	} else if (strcmp(arch, "aarch64") == 0) {
		current_arch = aarch64;
		return true;
	} else if (strcmp(arch, "x86_64") == 0) {
		current_arch = x86_64;
		return true;
	}
	return false;
}


bool is_indirect_branch(uint8_t *insn_data, size_t insn_size) 
{
	if (current_arch == x86_64) {
		// Handles callq rax, rcx, rdx, etc.
		if (insn_size == 2) {
			uint8_t b0 = insn_data[0];
			uint8_t b1 = insn_data[1];
			if ((b0 == 0xff) && (0xd0 <= b1) && (b1 <= 0xd6)) {
				// DEBUG_LOG("Found a `callq` instruction2: 0x%x%x\n", b0, b1);
				return true;
			}
		}
		// Handles callq r8, r9, r10, etc.
		if (insn_size == 3) {
			uint8_t b0 = insn_data[0];
			uint8_t b1 = insn_data[1];
			uint8_t b2 = insn_data[2];
			if ((b0 == 0x41) && (b1 == 0xff) && (0xd0 <= b2) && (b2 <= 0xd6)) {
				// DEBUG_LOG("Found a `callq` instruction3: 0x%x%x%x\n", b0, b1, b2);
				return true;
			}
		}
	}
	else if (current_arch == aarch64) {
		// Handles blr, br, b, etc.
		if (insn_size == 4) {
			uint8_t b0 = insn_data[0];
			uint8_t b1 = insn_data[1];
			uint8_t b2 = insn_data[2];
			uint8_t b3 = insn_data[3];
			if ((b0 == 0x00) && (b1 == 0x00) && (b2 == 0x1f) && (b3 == 0xd6)) {
				// DEBUG_LOG("Found a `blr` instruction: 0x%x%x%x%x\n", b0, b1, b2, b3);
				return true;
			}
		}
	}
	else if (current_arch == arm32) {
		// Handles blx, bx, b, etc.
		if (insn_size == 2) {
			uint8_t b0 = insn_data[0];
			uint8_t b1 = insn_data[1];
			if ((b0 == 0x1e) && (b1 == 0xff)) {
				// DEBUG_LOG("Found a `blx` instruction: 0x%x%x\n", b0, b1);
				return true;
			}
		}
	}
	return false;
}

#endif