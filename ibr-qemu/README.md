
### 编译  

qemu编译：
```
git clone https://github.com/qemu/qemu.git
git checkout tags/v9.0.2 
./configure --enable-plugins --target-list="x86_64-linux-user aarch64-linux-user"
make -j
```

### 实现思路  
**思路-1：** 识别调整指令，记录跳转目标的地址为dest addr (plugin1.c)  
在翻译阶段，插装block，判断是否有branch语句，在branch处指令运行阶段插装。  
执行到branch时，记录为caller_addr。跳转到目标block之后，记录dest_addr。  
> 思路1的问题：  
> 1. 多线程无法处理，qemu-user只有一个vcpu执行，并且无法识别线程，branch_addr (记录caller地址) 会被其他线程覆盖
> 2. mpis，jmp下的第一条指令会先于jmp执行，如果是普通指令就没影响，如果是jmp指令，就会有问题


**思路-2：** 识别跳转指令，直接从跳转指令解析出跳转目标 (plugin2.c)  


基于qemu实现存在的问题：  
- 分支不一定执行到，需要force execution技术
func_addr = NULL
if (flag) {
	func_addr = func1;
} else {
	func_addr = func2;
}
call(func_addr, args);


### 功能开发  

1. 实现version-1  
- （done）实现全部功能
- (done) 运行qemu自带的插件，例如：execlog看覆盖率
- (done) 写到三个测试用例

2. 在branch处indirect，实现x86_64和aarch64基本功能  
- 测试x86_64和aarch64基本架构  

3. 基于思路2指令解析来实现


4. 支持mips等更多架构

5. 判断是否是indirect branch  
- 用capstone重写
- 测试不同架构