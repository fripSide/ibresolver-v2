# 检查qemu自带的插件  

BINARY="../../new-qemu/tests/x86_64/2-muli-branch.elf"
BINARY="../../dev/test/x86_64/fn_ptr.elf"
QEMU="../qemu/build/qemu-x86_64"
PLUGIN="file=../qemu/build/contrib/plugins/libhowvec.so,inline=on,count=hint"
PLUGIN="file=../qemu/build/contrib/plugins/libexeclog.so"
# $QEMU -plugin $LIB,$LIB_ARGS -d plugin $BINARY 

QEMU_PLUGIN=$PLUGIN $QEMU -d plugin $BINARY

# -d plugin, enable plugin log