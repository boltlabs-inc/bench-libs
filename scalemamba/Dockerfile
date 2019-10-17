FROM ubuntu:16.04
WORKDIR /root
RUN apt-get update && apt-get install -y \
  bzip2 \
  doxygen \
  g++ \
  gcc \
  git \
  libcrypto++-dev \
  libgmp3-dev \
  m4 \
  make \
  patch \
  python \
  vim \
  wget \
  yasm \
  zip \
  gdb \
  tmux

ADD install_dependencies.sh .
RUN ["bash", "install_dependencies.sh"]

ADD source/ /root/source
ADD io_patch /root/io_patch
ADD data /root/data
ADD install.sh .
RUN ["bash", "install.sh"]

ADD README.md .

CMD ["/bin/bash"]
