BINARY="../../new-qemu/tests/x86_64/2-muli-branch.elf"
# BINARY="../../new-qemu/tests/x86_64/1-fn-ptr.elf"
LIB="./libibresolver.so"
LIB="./libibr2.so"
QEMU="../qemu/build/qemu-x86_64"
OUTPUT_CSV=2-muli-branch.csv
make
$QEMU -plugin $LIB,output="$OUTPUT_CSV" $BINARY 