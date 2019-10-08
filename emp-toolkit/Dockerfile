FROM ubuntu:16.04
WORKDIR /root
RUN apt-get update && apt-get install -y \
  build-essential \
  cmake \
  git \
  libgmp-dev \
  libssl-dev \
  sudo \
  software-properties-common \
  vim \
  wget
ADD install.sh .
RUN ["bash", "install.sh"]
ADD source/ .
RUN ["bash", "install_ripemd.sh"]
CMD ["/bin/bash"]

