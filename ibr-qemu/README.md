
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
> 2. mpis，branch指令BBlock下的第一条指令会先于branch（e.g., jmp, call）执行，如果是普通指令就没影响，如果是branch（e.g., jmp, call）指令，就会有问题


**思路-2：** 识别跳转指令，直接从跳转指令解析出跳转目标 (plugin2.c)  


基于qemu实现存在的问题：  
- 分支不一定执行到，需要force execution技术
```
func_addr = NULL
if (flag) {
	func_addr = func1;
} else {
	func_addr = func2;
}
func_addr(args);
```

### 功能开发  

1. （done）实现`思路1`  
- （done）实现全部功能
- (done) 运行qemu自带的插件，例如：execlog看覆盖率
- (done) 写到三个测试用例

2. 在branch处indirect，实现x86_64和aarch64基本功能  
- (done) 测试x86_64
- 测试aarch64基本架构  
- 基于xcross实现交叉编译
> export CROSS_TARGET=arm64-unknown-linux-musl

3. 基于`思路2`指令解析来实现  
https://shell-storm.org/online/Online-Assembler-and-Disassembler/
- dump指令，反编译指令


4. 支持mips等更多架构  
使用xcross项目来编译：https://github.com/Alexhuszagh/xcross

5. 判断是否是indirect branch  
- 用capstone重写
- 测试不同架构

6. 引入专用benchmark  
https://huhong789.github.io/papers/xia:deeptype.pdf  
