FROM nvidia/cuda:11.8.0-devel-ubuntu20.04@sha256:03681bbd11fea044ff3e3a5d65e190a6f935af30c56e03e740b27e4563f61e0f

ENV DEBIAN_FRONTEND=noninteractive
ENV CUDA_INSTALL_PATH=/usr/local/cuda
ENV PATH=/usr/local/cuda/bin:$PATH
ENV LD_LIBRARY_PATH=/usr/local/cuda/lib64:${LD_LIBRARY_PATH}

# Optional signed Ubuntu mirror; package authentication remains enabled.
ARG UBUNTU_MIRROR=
RUN if [ -n "${UBUNTU_MIRROR}" ]; then \
      case "${UBUNTU_MIRROR}" in https://*) ;; *) exit 2 ;; esac; \
      case "${UBUNTU_MIRROR}" in *[!A-Za-z0-9:/._-]*) exit 2 ;; esac; \
      sed -i "s|http://archive.ubuntu.com/ubuntu|${UBUNTU_MIRROR%/}|g; s|http://security.ubuntu.com/ubuntu|${UBUNTU_MIRROR%/}|g" /etc/apt/sources.list; \
    fi \
 && apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    make \
    bison \
    flex \
    zlib1g-dev \
    xutils-dev \
    libglu1-mesa-dev \
    libxi-dev \
    libxmu-dev \
    freeglut3-dev \
    libpng-dev \
    python3 python3-pip python3-tk python-is-python3 \
    doxygen graphviz \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Ubuntu 20.04's pip 20.x can fail while parsing current package indexes.
# pip 25.0.1 is the last pip release supporting the image's Python 3.8.
RUN python3 -m pip install --no-cache-dir --upgrade pip==25.0.1

RUN pip3 install --no-cache-dir \
    ply \
    Pmw \
    orjson==3.10.15 \
    zstandard==0.23.0 \
    numpy==1.24.4 \
    matplotlib==3.7.5

WORKDIR /workspace
CMD ["bash"]

COPY environment/dependencies.json /opt/sara/environment/dependencies.json
COPY scripts/prepare_simulator.py /opt/sara/scripts/prepare_simulator.py
COPY environment/build_simulator.sh /opt/sara/environment/build_simulator.sh
COPY fi/patches /opt/sara/fi/patches
COPY fi/parser_sources /opt/sara/fi/parser_sources
COPY provenance/native-sources.json /opt/sara/provenance/native-sources.json
RUN git clone --depth 1 --branch v4.2.0 https://github.com/gpgpu-sim/gpgpu-sim_distribution.git /tmp/sim-base \
 && python3 /opt/sara/scripts/prepare_simulator.py --upstream /tmp/sim-base --output /opt/simulator
RUN bash /opt/sara/environment/build_simulator.sh
COPY . /opt/sara
ENV PYTHONPATH=/opt/sara/sara/serial:/opt/sara/sara/serial/script/core:/opt/sara/sara/serial/script/common
WORKDIR /opt/sara

RUN ln -s /opt/simulator /native && ln -s /opt/simulator /native-memory-source \
 && rm /opt/sara/sara/serial/test_apps/.gitkeep /opt/sara/sara/parallel/test_apps/.gitkeep /opt/sara/gerem/test_apps/.gitkeep \
 && rmdir /opt/sara/sara/serial/test_apps /opt/sara/sara/parallel/test_apps /opt/sara/gerem/test_apps \
 && ln -s /opt/sara/benchmarks/apps /opt/sara/sara/serial/test_apps \
 && ln -s /opt/sara/benchmarks/apps /opt/sara/sara/parallel/test_apps \
 && ln -s /opt/sara/benchmarks/apps /opt/sara/gerem/test_apps
ENTRYPOINT ["python3", "/opt/sara/scripts/container_entrypoint.py"]
