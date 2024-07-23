
### ibr-qemu  
基于qemu插件来实现indirect branch解析。  

思路1：基于qemu-user执行程序，在跳转时记录跳转目标BBlock地址。  
思路2：基于qemu-user执行程序，在执行跳转指令时，手动解析跳转指令获取跳转目标。  

局限性：qemu无法覆盖全部分支，因此会遗漏部分间接跳转目标。  

[详细说明](ibr-qemu/README.md)

### ibr-fe
基于force execution来执行每一个分支。  

[详细说明](ibr-fe/README.md)

#### Indirect branch（简介跳转）  

[详细说明](ib.md)
