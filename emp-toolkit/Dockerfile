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
  unzip \
  vim \
  wget
ADD install.sh .
RUN ["bash", "install.sh"]

ADD install_testtools.sh .
RUN ["bash", "install_testtools.sh"]

ADD source/ .

ADD install_bolttools.sh .
RUN ["bash", "install_bolttools.sh"]

CMD ["/bin/bash"]

