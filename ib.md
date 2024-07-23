
## Indirect Branch  


## 基于Capstone来识别不同汇编指令  
https://www.cnblogs.com/N3ptune/p/16365790.html 

```
安装capstone:
sudo apt-get install libcapstone-dev
```

### x86_64汇编  
https://web.stanford.edu/class/archive/cs/cs107/cs107.1196/guide/x86-64.html

x86下应该有两种间接跳转：  
- jmp，直接跳转
- call，调用函数

https://gcc.gnu.org/bugzilla/show_bug.cgi?id=46219


#### 识别call指令  
https://portal.cs.umbc.edu/help/architecture/aig.pdf 
C5

