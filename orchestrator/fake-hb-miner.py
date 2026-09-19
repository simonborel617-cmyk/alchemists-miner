# -*- coding: utf-8 -*-
"""CPU stand-in for hb-miner's persist protocol, for testing the orchestrator without CUDA.
Reads `PARAMS <challenge> <floor> [addr1,addr2,...]` from stdin, hashes sha256(addr || nonce || challenge) for the
addresses round-robin and prints `FOUND addr=0x.. nonce_dec=.. challenge=0x.. bits=N` when leading-zero bits reach
that address's floor, then raises the floor to bits+1 (multi) or pauses until the next PARAMS (single, legacy).
Prints `STATS hashes=.. secs=.. rate=..` every 10 s like the real miner.
"""
import hashlib, os, sys, threading, time

def lz_bits(d):
    n = 0
    for by in d:
        if by == 0:
            n += 8
        else:
            for k in range(7, -1, -1):
                if by >> k & 1:
                    return n
                n += 1
    return 256

def main():
    addr = None
    for i, a in enumerate(sys.argv):
        if a == "--addr" and i + 1 < len(sys.argv):
            addr = sys.argv[i + 1]
    state = {"ch": None, "jobs": [], "multi": False, "paused": True, "gen": 0}
    lock = threading.Lock()

    def reader():
        for line in sys.stdin:
            line = line.strip()
            if line.startswith("QUIT"):
                os._exit(0)
            if line.startswith("PARAMS"):
                parts = line.split()
                if len(parts) >= 3:
                    floor = int(parts[2])
                    addrs = [x for x in parts[3].split(",") if len(x) >= 40] if len(parts) >= 4 else ([addr] if addr else [])
                    with lock:
                        state["ch"] = parts[1]
                        state["multi"] = len(parts) >= 4
                        state["jobs"] = [{"addr": a, "prefix": bytes.fromhex(a[2:] if a.startswith("0x") else a), "floor": floor} for a in addrs]
                        state["paused"] = not state["jobs"]
                        state["gen"] += 1
        os._exit(0)

    threading.Thread(target=reader, daemon=True).start()
    sys.stderr.write("fake-hb-miner persist: waiting for PARAMS\n")
    nonce = int(time.time()) << 20
    total = 0
    t0 = time.time()
    last_stats = t0
    j = 0
    while True:
        with lock:
            ch, jobs, multi, paused, gen = state["ch"], state["jobs"], state["multi"], state["paused"], state["gen"]
        if paused or not ch or not jobs:
            time.sleep(0.05)
            continue
        chb = bytes.fromhex(ch[2:].rjust(64, "0") if ch.startswith("0x") else ch.rjust(64, "0"))
        job = jobs[j % len(jobs)]
        j += 1
        best = None
        for _ in range(4000):
            nonce += 1
            total += 1
            d = hashlib.sha256(job["prefix"] + nonce.to_bytes(32, "big") + chb).digest()
            b = lz_bits(d)
            if b >= job["floor"] and (best is None or b > best[0]):
                best = (b, nonce)
        if best is not None:
            a = job["addr"] if job["addr"].startswith("0x") else "0x" + job["addr"]
            print("FOUND addr=%s nonce_dec=%d challenge=0x%s bits=%d" % (a, best[1], chb.hex(), best[0]), flush=True)
            with lock:
                if state["gen"] == gen:
                    if multi:
                        job["floor"] = best[0] + 1
                    else:
                        state["paused"] = True
        now = time.time()
        if now - last_stats >= 10:
            last_stats = now
            print("STATS hashes=%d secs=%d rate=%.6f" % (total, int(now - t0), total / (now - t0) / 1e9), flush=True)

if __name__ == "__main__":
    main()
