
QEMU_DIR=qemu

# 依赖
# sudo apt-get install libgtk2.0-dev
# sudo apt-get install libcapstone-dev
# sudo apt install xutils-dev

# mips-linux-user mips64-linux-user 
# mips64el-linux-user mipsel-linux-user 
# mipsn32-linux-user mipsn32el-linux-user

build_qemu() {
	if [ ! -d $QEMU_DIR ]; then
		git clone https://github.com/qemu/qemu.git qemu
		cd $QEMU_DIR
		git checkout tags/v9.0.2
		cd -
	fi

	if [ ! -d $QEMU_DIR/build ]; then
		cd $QEMU_DIR
		./configure --enable-plugins \
			--target-list="x86_64-linux-user aarch64-linux-user arm-linux-user mips-linux-user mipsel-linux-user mips64-linux-user mips64el-linux-user ppc64-linux-user ppc64le-linux-user riscv32-linux-user riscv64-linux-user"
		make -j
	fi
}

build_capstone() {
	if [ ! -d capstone ]; then
		git clone https://github.com/capstone-engine/capstone.git capstone
		cd capstone
		# git switch next
		cd -
	fi
	if [ ! -f libcapstone.so ]; then
		cd capstone
		CAPSTONE_ARCHS="arm aarch64 x86 mips powerpc riscv" ./make.sh install
	fi
}

build_qemu
build_capstone