# syntax=docker/dockerfile:1.4
FROM rust:1-buster

RUN apt update && apt install -qy cmake git build-essential libpcre2-dev libclang1 clang

RUN cargo install bindgen

RUN --mount=type=bind,source=sm/libyang,target=/root/sm/libyang,rw \
    cd /root/sm/libyang && mkdir build && cd build && \
    cmake -DENABLE_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE:String="Release" .. && \
    make install && ldconfig

RUN --mount=type=bind,source=sm/sysrepo,target=/root/sm/sysrepo,rw \
    cd /root/sm/sysrepo && mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
    make install && ldconfig

RUN --mount=type=bind,source=sm/yang2-rs,target=/root/sm/yang2-rs,rw \
    cd /root/sm/yang2-rs && cargo build
