LIB="./libibr2.so"
BIN="2-muli-branch.elf"
# BIN="1-fn-ptr.elf"
# BIN="1-arm-thumb.elf"


ARCH="x86_64"
# ARCH="arm"
ARCH="aarch64"
ARCH="mips"
ARCH="mipsel"
ARCH="mips64"
ARCH="mips64el"
ARCH="ppc64"
ARCH="ppc64le"
# ARCH="riscv32"
# ARCH="riscv64"

LIBC=""
QEMU="../qemu/build/qemu-${ARCH}"
BINARY="../tests/out/${ARCH}/${BIN}"

if [ $ARCH = "arm" ]; then
	QEMU="../qemu/build/qemu-arm"
	BINARY="../tests/out/arm/${BIN}"
	LIBC="-L /usr/arm-linux-gnueabi"
elif [ $ARCH = "aarch64" ]; then
	QEMU="../qemu/build/qemu-aarch64"
	BINARY="../tests/out/aarch64/${BIN}"
	LIBC="-L /usr/aarch64-linux-gnu"
fi



OUTPUT_CSV=results/${BIN}_${ARCH}.csv

make
$QEMU -plugin $LIB,output="$OUTPUT_CSV" $LIBC $BINARY 