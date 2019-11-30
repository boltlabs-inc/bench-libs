# put files in ther ight places
cd ~
mv  build_tokens/ emp-sh2pc/
rm emp-sh2pc/test/*
mv test/ emp-sh2pc/

# apply patch to add complement operation for integers
cd ~/emp-tool
git apply ~/integer.patch
make
make install

# build ripemd implementation
# (currently broken, not slated for fixing b/c we don't need it)
#mv ~/ripemd-160.cpp ~/emp-sh2pc/test/

# add unsigned integers
#cd ~/emp-tool
#git apply ~/uint.patch
#mv ~/uinteger.h* emp-tool/circuits/
#mv ~/uint.cpp test/
#cmake .
#make uint # maybe need to do more to install it later
#make install

# run our custom makefile
# (builds bolt library, bolt protocol, unit tests
cd ~/emp-sh2pc
mv ../CMakeLists.txt .
mkdir build
cd build
cmake ..
make all

# apply patch to update test code for ag2pc (it's broken)
cd ~/emp-ag2pc
# git apply ~/test.patch 



