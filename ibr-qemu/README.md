
当前进度：
- x86_64，支持
- arm，支持
- arm64，支持
- ppc32，qemu-user好像不支持
- ppc64，支持
- ppc64le，支持
- mips，plugin1支持（plugin2，指令解析无法读到寄存器）

### 编译  

qemu编译：
```
apt build-dep qemu
sudo cp /etc/apt/sources.list /etc/apt/sources.list~
sudo sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
sudo apt-get update
git clone https://github.com/qemu/qemu.git
git checkout tags/v9.0.2 
./configure --enable-plugins --target-list="x86_64-linux-user aarch64-linux-user"
make -j
```

capstone:
```
ubuntu 22.04自带的版本：libcapstone-dev
(4.0.2-5).
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

### 不同架构交叉编译和运行  

```
export CROSS_TARGET=arm64-unknown-linux-musl
xcross c++ main.c -o test
```

运行：
```
../qemu/build/qemu
```

### 功能开发  

1. （done）实现`思路1`  
- （done）实现全部功能
- (done) 运行qemu自带的插件，例如：execlog看覆盖率
- (done) 写到三个测试用例

2. (done)在branch处indirect，实现x86_64和aarch64基本功能  
- (done) 测试x86_64
- （done）基于xcross实现交叉编译
> export CROSS_TARGET=arm64-unknown-linux-musl
- (done) 切换回交叉编译工具
- （done）开发aarch64基本功能  
- （done）测试aarch64基本架构  


3. 基于`思路2`指令解析来实现  
https://shell-storm.org/online/Online-Assembler-and-Disassembler/
- （done）dump指令，反编译指令
- print_insn


4. 支持mips等更多架构  
- (done) 使用xcross项目来编译：https://github.com/Alexhuszagh/xcross
- todo: 都使用clang来编译
- mips
- riscv，切换最新的capstone


5. 支持更多indirect branch指令  
- 确认indirect branch是否完备  

5. 更多测试用例  
- gcc测试用例  

6. 引入专用benchmark  
https://huhong789.github.io/papers/xia:deeptype.pdf  


### Bug追踪

1. 1-fn-ptr用例，只显示一个jmp  
> 一条指令只触发了一次回调


2. mips，无法读到寄存器

3. capstone，不支持riscv
