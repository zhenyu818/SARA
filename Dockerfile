FROM nvidia/cuda:11.8.0-devel-ubuntu20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV CUDA_INSTALL_PATH=/usr/local/cuda
ENV PATH=/usr/local/cuda/bin:$PATH
ENV LD_LIBRARY_PATH=/usr/local/cuda/lib64:${LD_LIBRARY_PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
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

RUN pip3 install --no-cache-dir ply Pmw

WORKDIR /workspace
CMD ["bash"]
