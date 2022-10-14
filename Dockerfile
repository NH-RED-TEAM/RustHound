FROM rust:1.64-slim-buster

WORKDIR /usr/src/rusthound

RUN apt-get -y update && apt-get -y install gcc libclang-dev clang libclang-dev libgssapi-krb5-2 libkrb5-dev libsasl2-modules-gssapi-mit

COPY ./src/ ./src/
COPY ./Cargo.toml ./Cargo.toml

RUN cargo install --path .

ENTRYPOINT ["rusthound"]