FROM ubuntu:18.04

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
        build-essential \
        clang \
        curl \
        libcapstone-dev \
        wget

RUN cd && \
    wget https://github.com/Z3Prover/z3/archive/z3-4.7.1.tar.gz && \
    tar xf z3-4.7.1.tar.gz && \
    cd z3-z3-4.7.1/ && \
    ./configure && \
    cd build && \
    make -j 4 && \
    make install

RUN curl https://sh.rustup.rs -sSf > /tmp/install.sh && \
    chmod 755 /tmp/install.sh && \
    /tmp/install.sh -y