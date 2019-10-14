# apply patch to add complement operation for integers
cd ~/emp-tool
git apply ~/not_patch.diff
make
make install

# build ripemd implementation
# (currently broken, not slated for fixing b/c we don't need it)
mv ~/ripemd-160.cpp ~/emp-sh2pc/test/

cd ~/emp-sh2pc
echo "add_test (ripemd-160)" >> CMakeLists.txt
mkdir build
cd build
cmake ..
make ripemd-160

# apply patch to update test code for ag2pc
cd ~/emp-ag2pc
git apply ~/test.patch


