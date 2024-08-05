
## Indirect Branch  
间接跳转是指读取寄存器或者内存值来获取跳转地址，例如：  
> call rbx # x86_64
> blr r1 # aarch64

间接跳转分析（Indirect Branch Analysis）是分析出所有的可能的跳转地址。  

## 基于Capstone来识别不同汇编指令  
https://www.cnblogs.com/N3ptune/p/16365790.html 

```
安装capstone:
sudo apt-get install libcapstone-dev
```

## 不同架构开发  
交叉编译工具：  
1. xcross  
2. dockercross  
3. 直接安装对应的交叉编译工具  
1/2无法在容器中使用，因此放弃。由于我们只需要编译依赖libc的简单测试用例，因此选择在容器中直接安装交叉编译工具工具。


### x86_64汇编  
https://web.stanford.edu/class/archive/cs/cs107/cs107.1196/guide/x86-64.html

x86下应该有两种间接跳转：  
- jmp，直接跳转
- call，调用函数

https://gcc.gnu.org/bugzilla/show_bug.cgi?id=46219


#### 识别call指令  
https://portal.cs.umbc.edu/help/architecture/aig.pdf 
C5


### arm
https://azeria-labs.com/arm-on-x86-qemu-user/  
工具链安装:
```
# aarch64
gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu binutils-aarch64-linux-gnu-dbg 
# 编译工具链： aarch64-linux-gnu-gcc
# 运行： qemu-aarch64 -L /usr/aarch64-linux-gnu ./hello64dyn


# arm32
sudo apt install gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf binutils-arm-linux-gnueabihf-dbg  
# 编译工具链： arm-linux-gnueabihf-gcc -static -o hello32 hello32.c  
# 运行： qemu-arm -L /usr/arm-linux-gnueabihf ./hello32  
```

aarch64间接跳转：
> blr r1

### mips
mips       - MIPS (32-bit big endian)
mips64     - MIPS (64-bit big endian)
mips64el   - MIPS (64-bit little endian)
mipsel     - MIPS (32-bit little endian)
