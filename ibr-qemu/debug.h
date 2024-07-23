#pragma once

#include <stdio.h>
#include "qemu-plugin.h"

#define DEBUG

#ifdef DEBUG

#define DEBUG_LOG(fmt, ...) printf(fmt, ##__VA_ARGS__)

#define FATAL_ERR(fmt, ...)	\
	do {						\
		fprintf(stderr, "Fatal Error: " fmt, ##__VA_ARGS__);	\
		exit(-1);				\
	} while (0)

static GString* dump_insn(struct qemu_plugin_insn * insn)
{
	size_t insn_size = qemu_plugin_insn_size(insn);
	uint8_t *insn_opcode = (uint8_t *) qemu_plugin_insn_data(insn);

	GString *insn_op = g_string_new(NULL);
	for (int i = 0; i < insn_size; i++) {
		g_string_append_printf(insn_op, "%02x", insn_opcode[i]);
	}

	return insn_op;
}


#else // no DEBUG

#define DEBUG_LOG(fmt, ...)	\
	do {						\
	} while (0)	

#define FATAL_ERR(fmt, ...)	\
	do {						\
		exit(-1);				\
	} while (0)

static void dump_insn(uint8_t *insn_data, size_t insn_size) {}

#endif // end DEBUG
