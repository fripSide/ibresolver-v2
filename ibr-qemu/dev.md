
### 编译  

qemu编译：
```
git checkout tags/v9.0.2 
./configure --enable-plugins --target-list="x86_64-linux-user aarch64-linux-user"
make -j
```

### 实现思路  
思路-1：识别调整指令，记录跳转目标的地址为dest addr
在翻译阶段，插装block，判断是否有branch语句，在branch处指令运行阶段插装。
执行到branch时，记录为caller_addr。跳转到目标block之后，记录dest_addr。

思路-2：识别跳转指令，直接从跳转指令解析出跳转目标


问题：
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
- 实现全部功能
- 运行qemu自带的插件，例如：execlog看覆盖率
- 写到三个测试用例

2. 在branch处indirect，实现x86_64和aarch64基本功能  
- 测试x86_64和aarch64基本架构  

3. 判断是否是indirect branch  
- 用capstone重写
- 测试不同架构