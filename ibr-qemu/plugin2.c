// qemu/include/qemu/qemu-plugin.h
#include "qemu-plugin.h"
#include <stdio.h>
#include <stdbool.h>

#include "utils.h"
#include "debug.h"

// 思路2：跟踪指令，判断是否是间接跳转指令，解析当前指令，分别记录当前指令的地址（caller），和跳转地址(callee)  

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* 记录寄存器，在指令执行时解析指令中寄存器值获取跳转地址
*/

typedef struct {
	struct qemu_plugin_register *handle;
	GByteArray *last;
	GByteArray *new;
	const char *name;
} Register;

typedef struct CPU {
	/* Store last executed instruction on each vCPU as a GString */
	// GString *last_exec;
	struct qemu_plugin_insn *cur_insn;
	/* Ptr array of Register */
	GPtrArray *registers;
} CPU;

FILE *output;
static GArray *cpus;
static GRWLock expand_array_lock;

static void plugin_init(const qemu_info_t *info) 
{
	printf("QEMU Indirect Branch Resolver plugin loaded ~\n");
	printf("\tTarget Name: %s\n"
		"\tSMP VCPU: %d\n"
		"\tVCPU Num: %d\n",
		info->target_name,
		info->system.smp_vcpus,
		info->system.max_vcpus);

	cpus = g_array_sized_new(true, true, sizeof(CPU),
							info->system_emulation ? info->system.max_vcpus : 1);
}

static CPU *get_cpu(int vcpu_index)
{
	CPU *c;
	g_rw_lock_reader_lock(&expand_array_lock);
	c = &g_array_index(cpus, CPU, vcpu_index);
	g_rw_lock_reader_unlock(&expand_array_lock);

	return c;
}

static Register *init_vcpu_register(qemu_plugin_reg_descriptor *desc)
{
	Register *reg = g_new0(Register, 1);
	g_autofree gchar *lower = g_utf8_strdown(desc->name, -1);
	int r;

	reg->handle = desc->handle;
	reg->name = g_intern_string(lower);
	reg->last = g_byte_array_new();
	reg->new = g_byte_array_new();

	// DEBUG_LOG("init_vcpu_register: %s\n", reg->name);

	/* read the initial value */
	r = qemu_plugin_read_register(reg->handle, reg->last);
	g_assert(r > 0);
	return reg;
}

/* 可以只copy jmp指令中用到的寄存器？
*/
static GPtrArray *registers_init(int vcpu_index)
{
	g_autoptr(GPtrArray) registers = g_ptr_array_new();
	g_autoptr(GArray) reg_list = qemu_plugin_get_registers();

	if (reg_list->len) {
		for (int r = 0; r < reg_list->len; r++) {
			qemu_plugin_reg_descriptor *rd = &g_array_index(
				reg_list, qemu_plugin_reg_descriptor, r);
			Register *reg = init_vcpu_register(rd);
			g_ptr_array_add(registers, reg);
		}
	}

	return registers->len ? g_steal_pointer(&registers) : NULL;
}

/*
	根据寄存器名称，读寄存器的值：
	https://github.com/qemu/qemu/blob/master/include/qemu/qemu-plugin.h#L868
*/
static bool get_register_value(const char *reg_name, GByteArray *reg_val) 
{
	g_autoptr(GArray) reg_list = qemu_plugin_get_registers();
	if (reg_list->len) {
		for (int r = 0; r < reg_list->len; r++) {
			qemu_plugin_reg_descriptor *rd = &g_array_index(
				reg_list, qemu_plugin_reg_descriptor, r);
			if (g_str_equal(rd->name, reg_name)) {
				int res = qemu_plugin_read_register(rd->handle, reg_val);
				g_assert(res > 0);
				return true;
			}
		}
	}
	return false;
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

/*
 * Initialise a new vcpu/thread with:
 *   - last_exec tracking data
 *   - list of tracked registers
 *   - initial value of registers
 *
 * As we could have multiple threads trying to do this we need to
 * serialise the expansion under a lock.
 */
static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
	CPU *c;

	g_rw_lock_writer_lock(&expand_array_lock);
	if (vcpu_index >= cpus->len) {
		g_array_set_size(cpus, vcpu_index + 1);
	}
	g_rw_lock_writer_unlock(&expand_array_lock);

	c = get_cpu(vcpu_index);
	// c->last_exec = g_string_new(NULL);
	c->registers = registers_init(vcpu_index);
}

/* 直接从当前指令解析出跳转地址
*/
static void vcpu_insn_exec_with_regs(unsigned int cpu_index, void *udata)
{
	struct qemu_plugin_insn *insn = (struct qemu_plugin_insn *) udata;
	uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);
	uint32_t insn_opcode;
	insn_opcode = *((uint32_t *)qemu_plugin_insn_data(insn));
	const char *insn_disas = qemu_plugin_insn_disas(insn);

	// 1. 解析指令，通过名称找到对应的reg
	const char *reg_name = "rax";
	GByteArray *reg_val = g_byte_array_new();
	bool res = get_register_value(reg_name, reg_val);
	if (!res) {
		DEBUG_LOG("Failed to get register value: %s\n", reg_name);
		return;
	}
	// 2. 通过reg的handler 读取reg的值

	// 3. 解析出跳转地址

	GString *reg = g_string_new(NULL);
	for (int i = 0; i < reg_val->len; i++) {
		g_string_append_printf(reg, "%02x", g_array_index(reg_val, uint8_t, i));
	}

	printf("vcpu_insn_exec_with_regs: 0x%lx reg: %s\n", (uint64_t) udata, reg->str);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
	uint64_t vaddr = qemu_plugin_tb_vaddr(tb);
	uint64_t start_vaddr = qemu_plugin_tb_vaddr(tb);
	size_t num_insns = qemu_plugin_tb_n_insns(tb);

	for (int i = 0; i < num_insns; i++) {
		struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
		uint8_t *insn_data = (uint8_t *) qemu_plugin_insn_data(insn);

		// print_insn(insn);

		if (is_indirect_branch(insn_data, qemu_plugin_insn_size(insn))) {
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

	qemu_plugin_register_vcpu_init_cb(id, vcpu_init);

	// 解析indirect branch  
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

	return 0;
}