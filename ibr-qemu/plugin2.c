// qemu/include/qemu/qemu-plugin.h
#include "qemu-plugin.h"
#include <stdio.h>
#include <stdbool.h>

#include "utils.h"
#include "debug.h"
#include "cs_resolver.h"

// 思路2：跟踪指令，判断是否是间接跳转指令，解析当前指令，分别记录当前指令的地址（caller），和跳转地址(callee)  

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;


FILE *output;

static void plugin_init(const qemu_info_t *info) 
{
	printf("QEMU Indirect Branch Resolver plugin loaded ~\n");
	printf("\tTarget Name: %s\n"
		"\tSMP VCPU: %d\n"
		"\tVCPU Num: %d\n",
		info->target_name,
		info->system.smp_vcpus,
		info->system.max_vcpus);
}

/*
	根据寄存器名称，读寄存器的值：
	https://github.com/qemu/qemu/blob/master/include/qemu/qemu-plugin.h#L868
*/
static int get_register_value(const char *reg_name, GByteArray *reg_val) 
{
	g_autoptr(GArray) reg_list = qemu_plugin_get_registers();
	if (reg_list->len) {
		for (int r = 0; r < reg_list->len; r++) {
			qemu_plugin_reg_descriptor *rd = &g_array_index(
				reg_list, qemu_plugin_reg_descriptor, r);
			// printf("reg: %s %d\n", rd->name, r);
			if (g_str_equal(rd->name, reg_name)) {
				int res = qemu_plugin_read_register(rd->handle, reg_val);
				g_assert(res > 0);
				return res;
			}
		}
	}
	return 0;
}

static void print_insn(struct qemu_plugin_insn *insn)
{
	uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);
	uint32_t insn_opcode;
	insn_opcode = *((uint32_t *)qemu_plugin_insn_data(insn));
	const char *insn_disas = qemu_plugin_insn_disas(insn);
	char *output = g_strdup_printf("0x%"PRIx64", 0x%"PRIx32", \"disa: %s\"",
									insn_vaddr, insn_opcode, insn_disas);
	DEBUG_LOG("insn: -> %s\n", output);
}

/* 直接从当前指令解析出跳转地址
*/
static void vcpu_insn_exec_with_regs(unsigned int cpu_index, void *udata)
{
	struct qemu_plugin_insn *insn = (struct qemu_plugin_insn *) udata;
	uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);
	size_t insn_size = qemu_plugin_insn_size(insn);
	uint8_t *insn_opcode = (uint8_t *) qemu_plugin_insn_data(insn);
	const char *insn_disas = qemu_plugin_insn_disas(insn);
	GString* insn_op;
	int err_li = 0;
	const char *err_str = "";

	/* 疑似 insn_cb cache有bug，libc.so没有注册回调，也能触发
	*/
	bool is_ib = is_indirect_branch(insn_opcode, insn_size);
	// DEBUG_LOG("exec IB: %d %s\n", is_ib, insn_disas);
	if (!is_ib) {
		return;
	}

	// 1. 解析指令，通过名称找到对应的reg
	char reg_name[16] = {0};
	g_autoptr(GString) reg = g_string_new(NULL);
	bool suc = capstone_get_reg_name(insn_opcode, insn_size, reg_name);
	// printf("reg name: %s\n", reg_name);
	if (!suc) {
		err_li = __LINE__;
		err_str = "capstone_get_reg_name failed";
		goto failed;
	}

	GByteArray *reg_val = g_byte_array_new();
	int reg_sz = get_register_value(reg_name, reg_val);
	if (reg_sz <= 0) {
		err_li = __LINE__;
		goto failed;
	}
	uint64_t dest_val = 0;
	memcpy(&dest_val, reg_val->data, reg_val->len);

	uint64_t caller_inst_offset = 0;
	uint64_t dest_inst_offset = 0;
	char caller_image_name[512] = {0};
	char dest_image_name[512] = {0};
	bool res = covert_vaddr_to_offset(insn_vaddr, &caller_inst_offset, caller_image_name);
	if (!res) {
		err_li = __LINE__;
		goto failed;
	}
	res = covert_vaddr_to_offset(dest_val, &dest_inst_offset, dest_image_name);
	DEBUG_LOG("reg name: %s ins: %s reg-val: %s val: %lx off: %lx sz: %d\n", reg_name, insn_disas, reg->str, insn_vaddr, dest_inst_offset, reg_sz);
	fprintf(output, "0x%lx,0x%lx,0x%lx,0x%lx,%s,%s\n", caller_inst_offset, dest_inst_offset, 
		insn_vaddr, dest_val, caller_image_name, dest_image_name);
	return;
failed:
	insn_op = dump_insn(insn);
	DEBUG_LOG("Failed [%s] in line: %d reg: %s for insn: %s %s addr: %lx\n", err_str, err_li, reg_name, insn_op->str, insn_disas, insn_vaddr);
	exit(-1);
	g_string_free(insn_op, true);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
	size_t num_insns = qemu_plugin_tb_n_insns(tb);

	for (int i = 0; i < num_insns; i++) {
		struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
		uint8_t *insn_data = (uint8_t *) qemu_plugin_insn_data(insn);

		// print_insn(insn);

		bool is_ib = is_indirect_branch(insn_data, qemu_plugin_insn_size(insn));
		g_autoptr(GString) insn_op = dump_insn(insn);

		if (is_ib) {
			// DEBUG_LOG("IB: %d %s\n", is_ib, insn_op->str);
			qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec_with_regs,
				QEMU_PLUGIN_CB_R_REGS, (void *) insn);
		}
	}
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
	fclose(output);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
											const qemu_info_t *info,
											int argc, char **argv)
{
	if (!support_arch(info->target_name)) {
		DEBUG_LOG("ERROR: Unsupported architecture: %s\n", info->target_name);
		return -1;
	}

	if (argc < 1) {
		printf("Usage: /path/to/qemu \\ \n"
			"\t-plugin /path/to/libibr2.so,output=\"output.csv\",backend=\"/path/to/disassembly/libbackend.so\" \\ \n"
			"\t$BINARY\n");
		return -1;
	}

	const char *output_arg = argv[0] + sizeof("output=") - 1;
	output = fopen(output_arg, "w");
	if (!output) {
		DEBUG_LOG("ERROR: fopen %s failed\n", output_arg);
		return -1;
	}
	fprintf(output, "callsite offset,dest offset,callsite vaddr,dest vaddr,callsite ELF,dest ELF\n");


	plugin_init(info);

	// 解析indirect branch  
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

	return 0;
}