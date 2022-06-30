# syntax=docker/dockerfile:1.4
FROM rust:1-buster

RUN apt update && apt install -qy cmake git build-essential python3 python3-pip

RUN python3 -m pip install apkg

RUN --mount=type=bind,source=sm/libyang,target=/root/sm/libyang,rw \
    --mount=type=bind,source=.git/modules/sm/libyang,target=/root/.git/modules/sm/libyang,rw \
    cd /root/sm/libyang && apkg build -b && \
    mkdir -p /usr/share/debs/libyang && cp $(find ./pkg/build/pkgs | grep -e '\.deb$' ) /usr/share/debs/libyang/

RUN dpkg -i /usr/share/debs/libyang/*.deb

RUN apt update && apt install -qy quilt

RUN git config --global user.email "you@example.com"

RUN --mount=type=bind,source=sm/sysrepo,target=/root/sm/sysrepo,rw \
    --mount=type=bind,source=.git/modules/sm/sysrepo,target=/root/.git/modules/sm/sysrepo,rw \
    --mount=type=bind,source=patches/sysrepo,target=/root/patches \
    --mount=type=tmpfs,target=/root/.pc,rw \
    cd /root && quilt upgrade && quilt push -a && \
    cd /root/sm/sysrepo && git commit -a -m "tmp" && apkg build -b && \
    mkdir -p /usr/share/debs/sysrepo && cp $(find ./pkg/build/pkgs | grep -e '\.deb$' ) /usr/share/debs/sysrepo/

RUN dpkg -i /usr/share/debs/sysrepo/*.deb

RUN --mount=type=bind,source=sm/yang2-rs,target=/root/sm/yang2-rs,rw \
    --mount=type=bind,source=.git/modules/sm/yang2-rs,target=/root/.git/modules/sm/yang2-rs,rw \
    cd /root/sm/yang2-rs && cargo build

RUN cargo install bindgen

RUN apt install -qy libclang1 clang
