
import os
import sys

"""
解析list（asm）文件，检查运行结果是否正确
"""


"""
Ground Truth: 
MIPS -> 
  4004e8:	0320f809 	jalr	t9
  00400440 <add>:
  00400478 <sub>:


MIPSEL:
	004004b0 <call_with_args>:
		4004e8:	0320f809 	jalr	t9
	00400440 <add>:
	00400478 <sub>:

MIPS64:
	0000000120000e98 <call_with_args>:
		 120000ef0:	0320f809 	jalr	t9
		 120000f10:	0320f809 	jalr	t9
		 120000f30:	03e00008 	jr	ra

	0000000120000e10 <add>:
	0000000120000e54 <sub>:
"""

def check_result(res_path, arch):
	"""
	读取结果配置文件，来检查是否正确
	"""
	with open(res_path, 'r') as f
		res = f.readlines()
	
