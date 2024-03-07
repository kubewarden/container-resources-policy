# syntax=docker/dockerfile:1-labs

FROM alpine AS downloader
ADD --checksum=sha256:86a88ed80ba42d581f2139bfdcf1a6debeec558e3379ef85e69297579c758241 https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-16/libclang_rt.builtins-wasm32-wasi-16.0.tar.gz /
RUN tar xvf /libclang_rt.builtins-wasm32-wasi-16.0.tar.gz

FROM "tinygo/tinygo:0.31.1"
COPY --from=downloader /lib/wasi/libclang_rt.builtins-wasm32.a /usr/local/tinygo/lib/wasi-libc/sysroot/lib/wasm32-wasi/
COPY ./wasi.json /usr/local/tinygo/targets/wasi.json
