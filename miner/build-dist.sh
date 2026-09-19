#!/bin/bash
# Builds the release binary dist/hb-miner-linux-x64 on a CUDA devel box (run ON the box, e.g. via ssh_run):
# one fat binary for Turing, Ampere, Ada and Hopper (sm_75 / 80 / 86 / 89 / 90) plus PTX for anything newer.
#   scp miner/hb-miner.cu miner/build-dist.sh root@box:/root/ && ssh root@box "bash /root/build-dist.sh" && scp root@box:/root/hb-miner-linux-x64 dist/
set -e
export PATH=$PATH:/usr/local/cuda/bin
cd /root
command -v nvcc >/dev/null || { echo "nvcc not found: use a *-devel CUDA image"; exit 1; }
nvcc -O3 \
  -gencode arch=compute_75,code=sm_75 \
  -gencode arch=compute_80,code=sm_80 \
  -gencode arch=compute_86,code=sm_86 \
  -gencode arch=compute_89,code=sm_89 \
  -gencode arch=compute_90,code=sm_90 \
  -gencode arch=compute_90,code=compute_90 \
  hb-miner.cu -o hb-miner-linux-x64
./hb-miner-linux-x64 --selftest
ls -la hb-miner-linux-x64
echo DIST-BUILD-DONE
