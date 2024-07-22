

// qemu/include/qemu/qemu-plugin.h
#include "qemu-plugin.h"
#include <stdio.h>
#include <stdbool.h>

#include "backend.h"
#include "debug.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

FILE *output;
static GArray *cpus_branches;
static GRWLock expand_array_lock;

static void set_branch_addr(unsigned int cpu_index, uint64_t addr) 
{
	g_rw_lock_writer_lock(&expand_array_lock);
	uint64_t* branch_addr = &g_array_index(cpus_branches, uint64_t, cpu_index);
	*branch_addr = addr;
	g_rw_lock_writer_unlock(&expand_array_lock);
}

static uint64_t get_branch_addr(unsigned int cpu_index) 
{
	g_rw_lock_reader_lock(&expand_array_lock);
	uint64_t branch_addr = g_array_index(cpus_branches, uint64_t, cpu_index);
	g_rw_lock_reader_unlock(&expand_array_lock);
	return branch_addr;
}

static void plugin_init(const qemu_info_t *info) 
{
	printf("QEMU Indirect Branch Resolver plugin loaded ~\n");
	printf("\tTarget Name: %s\n"
		"\tSMP VCPU: %d\n"
		"\tVCPU Num: %d\n",
		info->target_name,
		info->system.smp_vcpus,
		info->system.max_vcpus);
	// system("cat /proc/self/maps");

	cpus_branches = g_array_sized_new(true, true, sizeof(uint64_t),
		info->system_emulation ? info->system.max_vcpus : 1);
}


// read virtual addr from /proc/self/maps
static bool resolve_inst_offset(uint64_t inst_addr, uint64_t *offset, char *image_name)
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
		if (inst_addr >= start && inst_addr <= end) {
			memcpy(image_name, pathname, strlen(pathname));
			*offset = inst_addr - start + addr_off;
			// printf("Found image: %s offset: %lx in\n", pathname, *offset);
			// DEBUG_LOG("Found image: %s offset: %lx\n", pathname, *offset);
			free(line);
			fclose(maps);
			return true;
		}
	}
	free(line);
	fclose(maps);
	return false;
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
	g_rw_lock_writer_lock(&expand_array_lock);
	if (vcpu_index >= cpus_branches->len) {
		g_array_set_size(cpus_branches, vcpu_index + 1);
	}
	g_rw_lock_writer_unlock(&expand_array_lock);
}

/* 记录indirect branch的jmp指令的地址
	下一个执行的block地址就是跳转地址
*/
static void check_and_record_ib(unsigned int cpu_index, void *udata)
{
	uint64_t branch_addr = get_branch_addr(cpu_index);

	if (branch_addr != 0) {
		uint64_t caller_inst_offset = 0;
		uint64_t dest_inst_offset = 0;
		char caller_image_name[512] = {0};
		char dest_image_name[512] = {0};
		bool res = resolve_inst_offset(branch_addr, &caller_inst_offset, caller_image_name);
		if (!res) {
			DEBUG_LOG("Failed to resolve instruction offset: 0x%lx\n", branch_addr);
			return;
		}

		uint64_t cur_insn_addr = (uint64_t) udata;
		res = resolve_inst_offset(cur_insn_addr, &dest_inst_offset, dest_image_name);

		if (!res) {
			DEBUG_LOG("Failed to resolve instruction offset: 0x%lx\n", cur_insn_addr);
			return;
		}

		// record ib insn
		// DEBUG_LOG("IB: %s 0x%lx -> %s 0x%lx\n", caller_image_name, caller_inst_offset, dest_image_name, dest_inst_offset);
		fprintf(output, "0x%lx,0x%lx,0x%lx,0x%lx,%s,%s\n", caller_inst_offset, dest_inst_offset, 
			branch_addr, cur_insn_addr, caller_image_name, dest_image_name);
	}
}

static void update_caller_insn_addr(unsigned int cpu_index, void *udata)
{
	set_branch_addr(cpu_index, (uint64_t)udata);
}

/* 非indirect branch的指令，重置caller的地址
*/
static void clear_caller_insn_addr(unsigned int cpu_index, void *udata)
{
	set_branch_addr(cpu_index, 0);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
	uint64_t vaddr = qemu_plugin_tb_vaddr(tb);
	uint64_t start_vaddr = qemu_plugin_tb_vaddr(tb);
	size_t num_insns = qemu_plugin_tb_n_insns(tb);
	char image_name[512] = {0};
	uint64_t inst_offset = 0;

	// DEBUG_LOG("TB: %p 0x%lx %ld insts\n", tb, vaddr, num_insns);

	/* 
	block1: # indirect branch
		jmp [rax + 0x22] # jmp to block2 func1

	block2: # func1 block
		...

	方法1：ibresolver的思路 (当前方法)
	在indirct branch处，记录caller的地址, jmp [rax + 0x22] # jmp to block func1
	在下一个block处(block2)，记录callee的地址 # func1 block，的地址

	方法2：直接在indirect branch处，解析出callee的地址, 设置inst_exec_cb到指令jmp [rax + 0x22]，回调的时候解析
	*/
	for (int i = 0; i < num_insns; i++) {
		struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
		uint8_t *insn_data = (uint8_t *) qemu_plugin_insn_data(insn);
		uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);

		bool is_ib = is_indirect_branch(insn_data, qemu_plugin_insn_size(insn));

		/* 起始块第一个指令，检查上一个block是否是indirect branch
		*/
		if (i == 0) {
			qemu_plugin_register_vcpu_insn_exec_cb(insn, check_and_record_ib,
				QEMU_PLUGIN_CB_NO_REGS, (void *)insn_vaddr);
		}

		/* 记录 indirect branch跳转地址，作为caller
		*/
		if (is_ib) {
			qemu_plugin_register_vcpu_insn_exec_cb(insn, update_caller_insn_addr,
					QEMU_PLUGIN_CB_NO_REGS, (void *)insn_vaddr);
		}

		/* 在下一条指令（从indirect jmp返回后）clear caller地址
			如果当前指令是最后一条，并且非jmp指令，就也clear地址
		*/
		if (i < num_insns - 1) {
			struct qemu_plugin_insn *next_insn = qemu_plugin_tb_get_insn(tb, i + 1);
				qemu_plugin_register_vcpu_insn_exec_cb(next_insn, clear_caller_insn_addr,
					QEMU_PLUGIN_CB_NO_REGS, NULL);
		} else if (i == num_insns - 1) {
			/* 如果当前指令是最后一条指令，并且不是indirect branch，clear caller地址
			*/
			if (!is_ib) {
				qemu_plugin_register_vcpu_insn_exec_cb(insn, clear_caller_insn_addr,
					QEMU_PLUGIN_CB_NO_REGS, NULL);
			}
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
			"\t-plugin /path/to/libibr.so,output=\"output.csv\",backend=\"/path/to/disassembly/libbackend.so\" \\ \n"
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

	// 根据线程数 (vcpu) 初始化数据结构  
	qemu_plugin_register_vcpu_init_cb(id, vcpu_init);

	// 解析indirect branch  
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
	return 0;
}