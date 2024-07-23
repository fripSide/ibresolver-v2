#include "utils.h"

#include <stdint.h>
#include <string.h>
#include <malloc.h>

#include "debug.h"
#include "cs_resolver.h"


static bool simple_is_indirect_branch(uint8_t *insn_data, size_t insn_size)
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

/*  version-1，利用capstone直接反编译，然后string里面遍历寄存器?
	version-2，解释执行这条指令
*/
bool is_indirect_branch(uint8_t *insn_data, size_t insn_size) 
{
	// return simple_is_indirect_branch(insn_data, insn_size);
	return capstone_is_indirect_branch(insn_data, insn_size);
}

// read virtual addr from /proc/self/maps, convert vaddr to offset
bool covert_vaddr_to_offset(uint64_t inst_vaddr, uint64_t *offset, char *image_name)
{
	FILE *maps = fopen("/proc/self/maps", "r");
	if (!maps) {
		perror("fopen");
		return false;
	}

	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	while ((read = getline(&line, &len, maps)) != -1) {
		uint64_t start, end;
		uint64_t addr_off = 0;
		char perms[5] = {0};
		char dev[6] = {0};
		int inode;
		char pathname[512] = {0};
		sscanf(line, "%lx-%lx %4s %lx %5s %d %s", &start, &end, perms, &addr_off, dev, &inode, pathname);
		if (inst_vaddr >= start && inst_vaddr <= end) {
			memcpy(image_name, pathname, strlen(pathname));
			*offset = inst_vaddr - start + addr_off;
			// DEBUG_LOG("Found image: %s start: %lx offset: %lx\n", pathname, start, addr_off);
			free(line);
			fclose(maps);
			return true;
		}
	}
	free(line);
	fclose(maps);
	return false;
}