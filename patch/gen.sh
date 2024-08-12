
# 生成qemu的修改patch

# tag 9.0.2
# 5ebde3b5c00e15f560f73055fac4ab31c0cac6d2

COMMIT=5ebde3b5c00e15f560f73055fac4ab31c0cac6d2

cd ../qemu
git diff > ../patch/qemu.patch
cd -