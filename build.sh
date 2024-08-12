
QEMU_DIR=qemu

# 依赖
# sudo apt-get install libgtk2.0-dev
# sudo apt-get install libcapstone-dev
# sudo apt install xutils-dev

# mips-linux-user mips64-linux-user 
# mips64el-linux-user mipsel-linux-user 
# mipsn32-linux-user mipsn32el-linux-user

install_deps() {
	if [ -f ./install_deps ]; then
		cat ./install_deps
		return
	fi

	# qemu
	sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
	sudo sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
	sudo apt-get update
	sudo apt build-dep qemu
	# capstone
	# sudo apt-get install libcapstone-dev
	echo "deps are installed" > ./install_deps
}

# 编译qemu和capstone
build_qemu() {
	if [ ! -d $QEMU_DIR ]; then
		git clone https://github.com/qemu/qemu.git qemu
		cd $QEMU_DIR
		git checkout tags/v9.0.2
		cd -
	fi

	if [ ! -f $QEMU_DIR/capstone/libcapstone.a ]; then
		cd $QEMU_DIR/capstone
		# need sudo
		CAPSTONE_ARCHS="arm aarch64 x86 mips powerpc riscv" ./make.sh install
		cd - 
	fi

	if [ ! -d $QEMU_DIR/build ]; then
		cd $QEMU_DIR
		export PKG_CONFIG_PATH=${PKG_CONFIG_PATH}:/usr/lib64/pkgconfig/
		./configure --enable-plugins --enable-capstone \
			--target-list="x86_64-linux-user aarch64-linux-user arm-linux-user mips-linux-user mipsel-linux-user mips64-linux-user mips64el-linux-user ppc64-linux-user ppc64le-linux-user riscv32-linux-user riscv64-linux-user"
		make -j
	fi
}

install_deps
build_qemu
