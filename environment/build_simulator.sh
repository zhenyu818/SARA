#!/usr/bin/env bash
set -euo pipefail
cd /opt/simulator
export CUDA_INSTALL_PATH=/usr/local/cuda
set +u
source setup_environment release
set -u
make -j4

