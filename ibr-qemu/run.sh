BINARY="../../new-qemu/tests/x86_64/2-muli-branch.elf"
BINARY="../../dev/test/x86_64/fn_ptr.elf"
LIB="./libibresolver.so"
LIB="./libibr.so"
QEMU="../qemu/build/qemu-x86_64"
OUTPUT_CSV="fn_ptr.csv"
make
$QEMU -plugin $LIB,output="$OUTPUT_CSV" $BINARY 