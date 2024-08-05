# 检查qemu自带的插件  

ARCH=mips

BINARY="../tests/out/$ARCH/1-fn-ptr.elf"
QEMU="../qemu/build/qemu-$ARCH"
PLUGIN="file=../qemu/build/contrib/plugins/libhowvec.so,inline=on,count=hint"
PLUGIN="file=../qemu/build/contrib/plugins/libexeclog.so"
# $QEMU -plugin $LIB,$LIB_ARGS -d plugin $BINARY 

QEMU_PLUGIN=$PLUGIN $QEMU -d plugin $BINARY reg=t9

# -d plugin, enable plugin log