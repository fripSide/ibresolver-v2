LIB="./libibr2.so"
BIN="2-muli-branch.elf"
BIN="1-fn-ptr.elf"


ARCH="x86_64"
ARCH="arm"
ARCH="aarch64"

LIBC=""

if [ $ARCH = "x86_64" ]; then
	QEMU="../qemu/build/qemu-x86_64"
	BINARY="../tests/out/x86_64/${BIN}"
elif [ $ARCH = "arm" ]; then
	QEMU="../qemu/build/qemu-arm"
	BINARY="../tests/out/arm/${BIN}"
	LIBC="-L /usr/arm-linux-gnueabi"
elif [ $ARCH = "aarch64" ]; then
	QEMU="../qemu/build/qemu-aarch64"
	BINARY="../tests/out/aarch64/${BIN}"
	LIBC="-L /usr/aarch64-linux-gnu"
else
	echo "Unsupported arch: $ARCH"
	exit 1
fi

OUTPUT_CSV=results/${BIN}_${ARCH}.csv

make
$QEMU -plugin $LIB,output="$OUTPUT_CSV" $LIBC $BINARY 