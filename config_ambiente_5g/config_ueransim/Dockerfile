FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y \
    cmake git gcc g++ libsctp-dev lksctp-tools iproute2
RUN git clone https://github.com/aligungr/UERANSIM && \
    cd UERANSIM && make -j$(nproc)

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    libsctp-dev \
    lksctp-tools \
    iproute2 \
    iperf3 \
    tcpdump \
    iputils-ping \
    && apt-get clean

COPY --from=builder /UERANSIM/build /ueransim/build
COPY --from=builder /UERANSIM/config /ueransim/config
WORKDIR /ueransim/build