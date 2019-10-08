#!/bin/bash

# install time command for better benchmarking
cd
wget https://ftp.gnu.org/gnu/time/time-1.9.tar.gz
tar xzvf time-1.9.tar.gz
rm time-1.9.tar.gz
cd time-1.9
./configure && make && make install

# run emp-toolkit tool install scripts 
cd
git clone https://github.com/emp-toolkit/emp-readme.git

bash ./emp-readme/scripts/install_packages.sh
apt-get install -y libboost-{chrono,log,program-options,date-time,thread,system,filesystem,regex,test}1.58-dev

bash ./emp-readme/scripts/install_relic.sh

#EC STRING SIZE - set extra relic parameters?
sed -i "s/FB_POLYN:STRING=283/FB_POLYN:STRING=251/" ~/relic/CMakeCache.txt
bash ./emp-readme/scripts/install_emp-tool.sh
bash ./emp-readme/scripts/install_emp-ot.sh

# install emp-toolkit semi-honest circuits (for testing and dev)
cd
git clone https://github.com/emp-toolkit/emp-sh2pc.git
mkdir emp-sh2pc/build


# install emp-toolkit malicious 2-party circuits
cd
git clone https://github.com/emp-toolkit/emp-ag2pc.git

#Fix space in error message
sed -i 's/{cout <<ands <<"no match GT!"<<endl<<flush;/{cout <<ands <<" no match GT!"<<endl<<flush;/' ~/emp-ag2pc/emp-ag2pc/2pc.h

mkdir emp-ag2pc/build
cd emp-ag2pc/build
cmake ..
make 

# install my vim scripts
cd
git clone https://github.com/marsella/vim.git
cp vim/.vimrc .


