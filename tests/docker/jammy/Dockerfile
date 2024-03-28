FROM ubuntu:jammy

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && apt upgrade -y
RUN apt install -y apt-utils
RUN apt install -y libccid \
    libpcsclite-dev \
    git \
    autoconf \
    pkg-config \
    libtool \
    help2man \
    automake \
    gcc \
    make \
    build-essential \
    opensc \
    python3 \
    python3-pip \
    swig \
    cmake \
    vsmartcard-vpcd \
    libgcrypt-dev \
    libssl-dev \
    check \
    gengetopt \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install pytest pycvc cryptography pyscard
RUN git clone https://github.com/Yubico/yubico-piv-tool
WORKDIR /yubico-piv-tool
RUN git checkout tags/yubico-piv-tool-2.5.1
ADD tests/docker/jammy/yubico-piv-tool.patch /yubico-piv-tool/yubico-piv-tool.patch
RUN git apply yubico-piv-tool.patch
RUN mkdir build
WORKDIR /yubico-piv-tool/build
RUN cmake .. -DENABLE_HARDWARE_TESTS=1
RUN make -j`nproc`
RUN make install
WORKDIR /
RUN ldconfig
