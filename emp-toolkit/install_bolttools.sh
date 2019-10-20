# apply patch to add complement operation for integers
#cd ~/emp-tool
#git apply ~/not_patch.diff
#make
#make install

# build ripemd implementation
# (currently broken, not slated for fixing b/c we don't need it)
#mv ~/ripemd-160.cpp ~/emp-sh2pc/test/

# add unsigned integers
cd ~/emp-tool
git apply ~/uint.patch
mv ~/uinteger.h* emp-tool/circuits/
mv ~/uint.cpp test/
cmake .
make uint # maybe need to do more to install it later

cd ~/emp-sh2pc

for TEST in ecdsa # ripemd-160
do
  mv ~/$TEST.cpp test/
  echo "add_test ($TEST)" >> CMakeLists.txt
  mkdir build
  cd build
  cmake ..
  make $TEST
done

# apply patch to update test code for ag2pc (it's broken)
cd ~/emp-ag2pc
# git apply ~/test.patch 



