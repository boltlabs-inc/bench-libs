
cd ~/emp-tool
git apply ~/not_patch.diff
make
make install

mv ~/ripemd-160.cpp ~/emp-sh2pc/test/

cd ~/emp-sh2pc
echo "add_test (ripemd-160)" >> CMakeLists.txt
mkdir build
cd build
cmake ..
make ripemd-160


