FROM rust:1.74-slim-buster

WORKDIR /usr/src/rusthound

RUN \
	apt-get -y update && \
	apt-get -y install gcc clang libclang-dev libgssapi-krb5-2 libkrb5-dev libsasl2-modules-gssapi-mit musl-tools make gcc-mingw-w64-x86-64 && \
	rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["make"]
