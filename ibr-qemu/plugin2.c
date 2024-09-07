// qemu/include/qemu/qemu-plugin.h
#include "glib.h"
#include "qemu-plugin.h"
#include <assert.h>
#include <glob.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#include "utils.h"
#include "debug.h"
#include "cs_resolver.h"

// 思路2：跟踪指令，判断是否是间接跳转指令，解析当前指令，分别记录当前指令的地址（caller），和跳转地址(callee)  

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct {
	struct qemu_plugin_register *handle;
	const char *name;
} Register;

typedef struct CPU {
	/* Ptr array of Register */
	GPtrArray *registers;
} CPU;

typedef struct CurrentInsn {
	uint64_t vaddr;
	uint8_t opcode[8];
	size_t opcode_len;
	char reg_name[16];
} CurrentInsn;


// output results
FILE *output;

// 保持每个vcpu的寄存器
static GArray *cpus;
static GRWLock expand_array_lock;
static GMutex add_reg_name_lock;

// 保持每条jmp指令
static GPtrArray *current_insns;
static GRWLock add_insns_lock;


static void plugin_init(const qemu_info_t *info) 
{
	printf("QEMU Indirect Branch Resolver plugin loaded ~\n");
	printf("\tTarget Name: %s\n"
		"\tSMP VCPU: %d\n"
		"\tVCPU Num: %d\n",
		info->target_name,
		info->system.smp_vcpus,
		info->system.max_vcpus);

	/* qemu-user下，只有一个vcpu，是不需要锁和多个数组的。
		为了后面兼容qemu-system，针对每个vcpu都分配单独的寄存器。
	*/
	cpus = g_array_sized_new(true, true, sizeof(CPU),
							info->system_emulation ? info->system.max_vcpus : 1);
	current_insns = g_ptr_array_new();
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

	return reg;
}

static CurrentInsn *alloc_insn()
{
	CurrentInsn *cinsn = g_new0(CurrentInsn, 1);
	g_rw_lock_writer_lock(&add_insns_lock);
	g_ptr_array_add(current_insns, cinsn);
	g_rw_lock_writer_unlock(&add_insns_lock);
	return cinsn;
}

static void free_all_insn(void)
{
	for (int i = 0; i < current_insns->len; i++) {
		CurrentInsn *cinsn = g_ptr_array_index(current_insns, i);
		g_free(cinsn);
	}
	g_ptr_array_free(current_insns, true);
}

static GPtrArray *registers_init(int vcpu_index)
{
	g_autoptr(GPtrArray) registers = g_ptr_array_new();
	g_autoptr(GArray) reg_list = qemu_plugin_get_registers();

	DEBUG_LOG("init n register: %d\n", reg_list->len);

	if (reg_list->len) {
		/* TODO: 只需要追踪jmp/call用到的寄存器
		* Go through each register in the complete list and
		* see if we want to track it.
		*/
		for (int r = 0; r < reg_list->len; r++) {
			qemu_plugin_reg_descriptor *rd = &g_array_index(
				reg_list, qemu_plugin_reg_descriptor, r);
			Register *reg = init_vcpu_register(rd);
			g_ptr_array_add(registers, reg);
		}
	}

	return registers->len ? g_steal_pointer(&registers) : NULL;
}


static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
	CPU *c;

	g_rw_lock_writer_lock(&expand_array_lock);
	if (vcpu_index >= cpus->len) {
		g_array_set_size(cpus, vcpu_index + 1);
	}
	g_rw_lock_writer_unlock(&expand_array_lock);

	c = get_cpu(vcpu_index);
	c->registers = registers_init(vcpu_index);

	printf("init cpu: %u\n", vcpu_index);
}


/*
MPIS: 无法读到寄存器
根据name读取寄存器是否合适？能否直接根据寄存器编号id来读？
https://github.com/capstone-engine/capstone/blob/next/arch/Mips/MipsMapping.c#L202

保证capstone和gdb-xml把寄存器排列顺序一致，比保证两边命名一致更难。
所以还是继续用名称来找
*/
static int get_register_value_vcpu(int vcpu, const char *reg_name, GByteArray *reg_val) 
{
	CPU *cpu = get_cpu(vcpu);
	GPtrArray* reg_list = cpu->registers; 
	// printf("reg list: %d\n", reg_list->len);
	if (reg_list->len) {
		for (int r = 0; r < reg_list->len; r++) {
			// qemu_plugin_reg_descriptor *rd = &g_array_index(
			// 	reg_list, qemu_plugin_reg_descriptor, r);
			Register *rd = g_ptr_array_index(reg_list, r);
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

/* 直接从当前指令解析出跳转地址
*/
static void vcpu_insn_exec_with_regs(unsigned int cpu_index, void *udata)
{
	CurrentInsn *cinsn = (CurrentInsn *) udata;
	uint64_t insn_vaddr = cinsn->vaddr;
	uint64_t dest_val = 0;
	int err_li = 0;
	const char *err_str = "";
	uint64_t caller_inst_offset = 0;
	uint64_t dest_inst_offset = 0;
	char caller_image_name[512] = {0};
	char dest_image_name[512] = {0};


	GByteArray *reg_val = g_byte_array_new();
	int reg_sz = get_register_value_vcpu(cpu_index, cinsn->reg_name, reg_val);
	if (reg_sz <= 0) {
		err_li = __LINE__;
		err_str = "read reg value failed";
		goto failed;
	}
	
	// 需要大小端转换
	copy_reg_value(&dest_val, reg_val->data, reg_val->len, is_big_endian());

	bool res = covert_vaddr_to_offset(insn_vaddr, &caller_inst_offset, caller_image_name);
	if (!res) {
		err_li = __LINE__;
		err_str = "covert caller vaddr failed";
		goto failed;
	}
	res = covert_vaddr_to_offset(dest_val, &dest_inst_offset, dest_image_name);
	if (!res) {
		err_li = __LINE__;
		err_str = "covert dest vaddr failed";
		goto failed;
	}

	// 保持结构到 output.csv
	DEBUG_LOG("\tread reg -> name: %s val: %lx addr: %lx off: %lx sz: %d\n", cinsn->reg_name, dest_val, insn_vaddr, dest_inst_offset, reg_sz);
	fprintf(output, "0x%lx, 0x%lx, 0x%lx, 0x%lx, %s, %s\n", caller_inst_offset, dest_inst_offset, 
		insn_vaddr, dest_val, caller_image_name, dest_image_name);
	return;
failed:
	DEBUG_LOG("\tFailed [%s] in line: %d reg: %s ins-addr: %lx dest-addr: 0x%lx\n", err_str, err_li, cinsn->reg_name, insn_vaddr, dest_val);
	exit(-1);
	return;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
	size_t num_insns = qemu_plugin_tb_n_insns(tb);

	for (int i = 0; i < num_insns; i++) {
		struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
		uint8_t *insn_opcode = (uint8_t *) qemu_plugin_insn_data(insn);
		size_t insn_size = qemu_plugin_insn_size(insn);
		// print_insn(insn);

		bool is_ib = is_indirect_branch(insn_opcode, insn_size);

		/* 如果是间接跳转，就保持读取的寄存器
		*/
		if (is_ib) {
			uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);
			CurrentInsn *cinsn = alloc_insn();
			cinsn->vaddr = insn_vaddr;

			bool suc = capstone_get_reg_name(insn_opcode, insn_size, cinsn->reg_name);

			if (!suc) {
				DEBUG_LOG("\t[WARN] capstone_get_reg_name failed\n");
				continue;
			}

			DEBUG_LOG("IB: %lx\n\t", insn_vaddr);
			print_insn(insn);

			/* 这里的callback userdata，不能传指令引用，会被释放reuse。因此需要自定义结构体cinsn，等运行完再释放
			*/
			qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec_with_regs,
				QEMU_PLUGIN_CB_R_REGS, (void *) cinsn);
		}
	}
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
	free_all_insn();
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

	// 初始化寄存器
	qemu_plugin_register_vcpu_init_cb(id, vcpu_init);

	// 解析indirect branch  
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

	return 0;
}
