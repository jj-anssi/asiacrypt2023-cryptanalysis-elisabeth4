FROM ubuntu:22.04
WORKDIR /app/
ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update                                                 && \
    apt-get install -qy --no-install-recommends                       \
        libm4ri-dev                                                   \
        libgsl-dev                                                    \
        libgmp-dev                                                    \
        libssl-dev                                                    \
        libomp-dev                                                    \
        make                                                          \
        cmake                                                         \
        python3                                                       \
        build-essential                                               \
        git                                                        && \
    apt-get clean                                                  && \
    rm -rf /var/lib/apt/lists/                                     && \
    useradd -d /home/cryptanalysis -m cryptanalysis -s /bin/bash   && \
    git config --global http.sslverify false                       && \
    git clone https://gitlab.inria.fr/cado-nfs/cado-nfs.git /cado  && \
    cd /cado                                                       && \
    make -j8

ENV PATH="/cado/build/buildkitsandbox/linalg/bwc:$PATH"
USER cryptanalysis
