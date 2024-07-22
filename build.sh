
QEMU_DIR=qemu

build_qemu() {
	if [ ! -d $QEMU_DIR ]; then
		git clone https://github.com/qemu/qemu.git $QEMU_DIR
		cd $QEMU_DIR
		git checkout tags/v9.0.2 
	fi

	if [ ! -d $QEMU_DIR/build ]; then
		cd $QEMU_DIR
		./configure --enable-plugins --target-list="x86_64-linux-user aarch64-linux-user"
		make -j
	fi
}

build_qemu