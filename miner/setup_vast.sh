#!/bin/bash
# Builds hb-miner on a GPU box (Vast). Run ON the box (or through ssh_run). Needs a *-devel CUDA image with nvcc.
set -e
export PATH=$PATH:/usr/local/cuda/bin
cd /root
command -v nvcc >/dev/null || { echo "nvcc not found: use a *-devel CUDA image"; exit 1; }

# compute capability of the card -> -arch
CC=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | head -1 | tr -d '.')
echo "compute_cap=$CC  gpu=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)"
ARCH="sm_${CC}"
if ! nvcc -O3 -arch=${ARCH} hb-miner.cu -o hb-miner 2>/tmp/nvcc.err; then
  echo "build for ${ARCH} failed, falling back to -arch=compute_90 (PTX):"; tail -3 /tmp/nvcc.err
  nvcc -O3 -arch=compute_90 -code=compute_90 hb-miner.cu -o hb-miner
fi
echo "=== selftest ==="
./hb-miner --selftest
echo "=== bench 20s ==="
./hb-miner --addr 0x1111111111111111111111111111111111111111 \
           --challenge 0x4242424242424242424242424242424242424242424242424242424242424242 \
           --benchsecs 20
echo DONE
