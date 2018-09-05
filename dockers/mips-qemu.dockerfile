FROM debian:stretch

RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y \
        build-essential \
        qemu-user-static \
        wget

RUN cd && \
    wget http://ftp.gnu.org/gnu/gdb/gdb-8.1.tar.gz && 
    tar xf gdb-8.1.tar.gz && \
    cd gdb-8.1 && \
    ./configure && \
    make -j 6 && \
    make install
