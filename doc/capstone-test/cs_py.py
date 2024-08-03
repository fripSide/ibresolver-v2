
from capstone import *
from capstone.arm64 import *

CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"
CODE = b"\xff\xd5"
CODE = b"\xe8\xb6\x29\x02\x00"
CODE = b"\xe8\xa7\xfc\xff\xff"
CODE = b"\xff\xd5"
CODE = b"\xd6\x3f\x00\x40"
CODE = b"\xc1\x03\x00\xb4"
# CODE = b"\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b"

# md = Cs(CS_ARCH_X86, CS_MODE_64)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
for i in md.disasm(CODE, 0x1000):
	print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
	print("CS_GRP_CALL", CS_GRP_CALL in i.groups)
	print("CS_GRP_BRANCH_RELATIVE", CS_GRP_BRANCH_RELATIVE in i.groups)
	print("CS_GRP_JUMP", CS_GRP_JUMP in i.groups)
	print(i.regs_read)
	for op in i.operands:
		print(op)
	print(i.op_str, len(i.regs_read))
	for r in i.regs_read:
		print("%s " %i.reg_name(r)),