FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bison \
        build-essential \
        ca-certificates \
        flex \
        libdumbnet-dev \
        libluajit-5.1-dev \
        liblzma-dev \
        libnghttp2-dev \
        libpcre3-dev \
        libpcap-dev \
        libssl-dev \
        pkg-config \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY daq-2.0.7.tar.gz snort-2.9.20.tar.gz /tmp/

RUN tar -xzf /tmp/daq-2.0.7.tar.gz -C /tmp \
    && cd /tmp/daq-2.0.7 \
    && ./configure --prefix=/usr/local \
    && make -j1 \
    && make install \
    && ldconfig \
    && tar -xzf /tmp/snort-2.9.20.tar.gz -C /tmp \
    && cd /tmp/snort-2.9.20 \
    && CPPFLAGS="-I/usr/include/tirpc" ./configure --enable-sourcefire --prefix=/usr/local \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && mkdir -p /etc/snort /var/log/snort

COPY snort.conf /etc/snort/snort.conf

ENTRYPOINT ["snort"]
