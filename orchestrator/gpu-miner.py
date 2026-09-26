# -*- coding: utf-8 -*-
"""GPU orchestrator for the Alchemists Mine, built on Hash Broker's hb-miner persist protocol.

Each box runs one `hb-miner --persist` process (locally, via `wsl`, or over ssh) and reads
`PARAMS <challenge> <floor> <addr1,addr2,...>` lines from stdin; it hashes the addresses round-robin,
ratchets every address's floor on its own and prints `FOUND addr=0x.. nonce_dec=.. challenge=0x.. bits=N`
plus `STATS hashes=.. secs=.. rate=..` every 10 s. The preimage is byte-identical to Hash Broker's:
sha256(miner(20) || nonce(32 BE) || challenge(32)).

Several miner accounts share every box: with --miners-file all keys (up to 32) go into one PARAMS line
per box and each submits from its own address.

Per chain session m:
  * make sure challenge[m] exists (tick if not),
  * send PARAMS challenge[m] floor(minuteThreshold[m]) <addresses> to every box,
  * on every FOUND: verify locally and keep that address's best of the minute,
  * once an address holds a find that clears the exact threshold, re-send PARAMS for minute m to every box without
    that address: the tier is rolled at reveal from a random seed, so a higher hash buys nothing and an address can
    submit once per minute. When every address has a find, nothing is sent; the next minute carries the full list,
  * when session m+1 begins: every miner submits its best find of m in parallel (pays currentPrice),
    which also reveals older finds.

  python scripts/gpu-miner.py --net robinhoodTestnet --box "ssh -p 30596 root@ssh9.vast.ai ./hb-miner"
  python scripts/gpu-miner.py --net robinhoodTestnet --box "ssh ... ./hb-miner" --miners-file .env.miners
  python scripts/gpu-miner.py --net localhost --box "python scripts/fake-hb-miner.py" --dry
Keys: --miners-file (one private key per line) or MINER_KEY / DEPLOYER_KEY from .env. Stop: create gpu-stop.txt.
"""
import argparse, hashlib, json, math, os, re, shlex, subprocess, sys, threading, time, urllib.request
from concurrent.futures import ThreadPoolExecutor
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
from eth_account import Account
from eth_utils import keccak

ROOT = os.path.dirname(os.path.abspath(__file__))
# frozen (PyInstaller): deployments/, .env, logs and the stop file live next to the executable
PROJ = os.path.dirname(os.path.abspath(sys.executable)) if getattr(sys, "frozen", False) else os.path.dirname(ROOT)

def load_env():
    env = {}
    p = os.path.join(PROJ, ".env")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    env.update({k: v for k, v in os.environ.items() if k in ("MINER_KEY", "DEPLOYER_KEY", "ROBINHOOD_TESTNET_RPC", "ROBINHOOD_RPC", "RPC_URL")})
    return env

def sel(sig):
    return "0x" + keccak(text=sig)[:4].hex()

SEL = {
    "challenge": sel("challenge(uint64)"),
    "minuteThreshold": sel("minuteThreshold(uint64)"),
    "currentPrice": sel("currentPrice()"),
    "tick": sel("tick()"),
    "submit": sel("submit(uint64,uint256)"),
    "reveal": sel("reveal(address)"),
    "pendingCount": sel("pendingCount(address)"),
    "tQ8": sel("tQ8()"),
    "unlockedTier": sel("unlockedTier()"),
    "sessionSec": sel("sessionSec()"),
    "oreRemaining": sel("oreRemaining()"),
}
TOPIC_MINED = "0x" + keccak(text="Mined(address,uint8,uint8,uint256,bool)").hex()
TOPIC_KEY = "0x" + keccak(text="KeyMined(address,uint8)").hex()
GAS = {"tick": 3_000_000, "submit": 1_500_000, "reveal": 1_000_000}

LOG_LOCK = threading.Lock()
def log(m):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), m)
    with LOG_LOCK:
        print(line, flush=True)
        try:
            open(os.path.join(PROJ, "gpu-miner.log"), "a", encoding="utf-8").write(line + "\n")
        except Exception:
            pass

# ------------------------------------------------------------------ work (mirrors FixedMath.workQ8)
def log2q8(x):
    n = x.bit_length() - 1
    m = x >> (n - 127) if n >= 127 else x << (127 - n)
    frac = 0
    for _ in range(8):
        m = (m * m) >> 127
        frac <<= 1
        if m >= (1 << 128):
            frac |= 1
            m >>= 1
    return (n << 8) | frac

def work_q8(digest):
    x = int.from_bytes(digest, "big")
    return 65535 if x == 0 else 65536 - log2q8(x)

def digest_of(addr, nonce, chx):
    msg = bytes.fromhex(addr[2:]) + int(nonce).to_bytes(32, "big") + bytes.fromhex(chx[2:].rjust(64, "0"))
    return hashlib.sha256(msg).digest()

# ------------------------------------------------------------------ rpc
class Rpc:
    def __init__(self, url):
        self.url = url

    def call(self, method, params, tmo=25):
        d = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, d, {"Content-Type": "application/json", "User-Agent": "alchemists-gpu/0.2"})
        return json.loads(urllib.request.urlopen(req, timeout=tmo).read())

class Chain:
    """Read-only view of the Mine plus chain-time bookkeeping (shared by all miners)."""
    def __init__(self, rpc, chain_id, mine):
        self.rpc, self.chain_id, self.mine = rpc, chain_id, mine
        self.offset = 0.0
        self.session = 60

    def view(self, data, frm=None, value=0):
        call = {"to": self.mine, "data": data, "value": hex(value)}
        if frm:
            call["from"] = frm
        r = self.rpc.call("eth_call", [call, "latest"])
        if "error" in r:
            raise RuntimeError(r["error"].get("message", str(r["error"])))
        return r["result"]

    @staticmethod
    def u64arg(v):
        return int(v).to_bytes(32, "big").hex()

    def challenge(self, m):
        return self.view(SEL["challenge"] + self.u64arg(m))

    def minute_threshold(self, m):
        return int(self.view(SEL["minuteThreshold"] + self.u64arg(m)), 16)

    def price(self):
        return int(self.view(SEL["currentPrice"]), 16)

    def unlocked(self):
        return int(self.view(SEL["unlockedTier"]), 16)

    def ore(self):
        return int(self.view(SEL["oreRemaining"]), 16)

    def pending(self, addr):
        return int(self.view(SEL["pendingCount"] + addr[2:].rjust(64, "0")), 16)

    def sync_time(self):
        blk = self.rpc.call("eth_getBlockByNumber", ["latest", False])["result"]
        ts = int(blk["timestamp"], 16)
        off = ts - time.time()
        if off > -15:
            self.offset = off
        return ts

    def now(self):
        return time.time() + self.offset

    def minute(self):
        return int(self.now() // self.session)

class Account_:
    """One signing account: nonce-serialized sends."""
    def __init__(self, chain, key):
        self.chain = chain
        self.acct = Account.from_key(key)
        self.address = self.acct.address
        self.lock = threading.Lock()

    def send(self, data, value, gas, label):
        rpc = self.chain.rpc
        with self.lock:
            blk = rpc.call("eth_getBlockByNumber", ["latest", False])["result"]
            base = int(blk.get("baseFeePerGas", "0x5f5e100"), 16)
            nn = int(rpc.call("eth_getTransactionCount", [self.address, "pending"])["result"], 16)
            tx = {"chainId": self.chain.chain_id, "nonce": nn, "to": self.chain.mine, "value": int(value), "data": data, "gas": gas,
                  "maxFeePerGas": int(base * 2 + 10_000_000), "maxPriorityFeePerGas": 1_000_000, "type": 2}
            signed = self.acct.sign_transaction(tx)
            raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
            raw = raw.hex() if isinstance(raw, (bytes, bytearray)) else raw
            if not raw.startswith("0x"):
                raw = "0x" + raw
            r = rpc.call("eth_sendRawTransaction", [raw])
            if "error" in r:
                log("%s %s: send error %s" % (self.address[:8], label, r["error"].get("message")))
                return None, None
            h = r["result"]
            for _ in range(150):
                rc = rpc.call("eth_getTransactionReceipt", [h]).get("result")
                if rc:
                    return h, rc
                time.sleep(0.4)
            return h, None

    def tick(self):
        h, rc = self.send(SEL["tick"], 0, GAS["tick"], "tick")
        return rc is not None and rc.get("status") == "0x1"

    def reveal(self):
        h, rc = self.send(SEL["reveal"] + self.address[2:].rjust(64, "0"), 0, GAS["reveal"], "reveal")
        return rc

    def submit(self, for_minute, nonce, value):
        data = SEL["submit"] + Chain.u64arg(for_minute) + int(nonce).to_bytes(32, "big").hex()
        try:
            self.chain.view(data, self.address, value)  # dry run against the latest state
        except Exception as e:
            msg = str(e)
            log("%s submit dry run reverted, skipping: %s" % (self.address[:8], msg[:120]))
            return None, (None if "Mine: price" in msg else False)
        return self.send(data, value, GAS["submit"], "submit")

# ------------------------------------------------------------------ miner processes
class Box:
    """One hb-miner process per card, shared by every miner address: PARAMS carries the address list and the
    miner hashes them round-robin, ratcheting each address's floor on its own. FOUND lines name the address.
    Within a minute the orchestrator re-sends PARAMS with a shorter list as addresses get a qualifying find; every
    PARAMS makes hb-miner pick a fresh random nonce base and reset the floors, so no hash is repeated."""
    def __init__(self, cmd, default_addr, on_found, tag):
        self.cmd, self.default_addr, self.on_found, self.tag = cmd, default_addr, on_found, tag
        self.proc = None
        self.alive = False
        self.wlock = threading.Lock()
        self.started = 0
        self.strikes = 0
        self.rate = 0.0  # GH/s reported by the miner's STATS lines
        self.hashes = 0
        self.last = None  # (chx, floor, addrs) to replay after a restart

    def start(self):
        args = shlex.split(self.cmd, posix=(os.name != "nt")) + ["--addr", self.default_addr, "--persist"]
        self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1, cwd=PROJ)
        self.alive = True
        self.started = time.time()
        threading.Thread(target=self.reader, daemon=True).start()
        log("box started: %s" % self.tag)

    def params(self, chx, floor, addrs):
        self.last = (chx, floor, addrs)
        if not self.alive:
            return
        with self.wlock:
            try:
                self.proc.stdin.write("PARAMS %s %d %s\n" % (chx, floor, ",".join(addrs)))
                self.proc.stdin.flush()
            except Exception:
                self.dead()

    def dead(self):
        if self.alive:
            self.alive = False
            if time.time() - self.started < 30:
                self.strikes += 1
            log("box died: %s (strikes %d)" % (self.tag, self.strikes))

    def reader(self):
        try:
            for line in self.proc.stdout:
                m = re.search(r"FOUND (?:addr=(0x[0-9a-fA-F]{40}) )?nonce_dec=(\d+) challenge=(0x[0-9a-fA-F]+)", line)
                if m:
                    self.on_found(self, m.group(1) or self.default_addr, int(m.group(2)), m.group(3))
                    continue
                s = re.search(r"STATS hashes=(\d+) secs=(\d+) rate=([\d.]+)", line)
                if s:
                    self.hashes, self.rate = int(s.group(1)), float(s.group(3))
        except Exception:
            pass
        self.dead()

    def quit(self):
        try:
            self.proc.stdin.write("QUIT\n")
            self.proc.stdin.flush()
        except Exception:
            pass
        try:
            self.proc.terminate()
        except Exception:
            pass

# ------------------------------------------------------------------ miners
class Miner:
    def __init__(self, idx, account, chain, dry):
        self.idx, self.account, self.chain, self.dry = idx, account, chain, dry
        self.tag = "m%d:%s" % (idx, account.address[:8])
        self.cur = {"minute": None, "ch": None, "floor": None, "tq8": None}
        self.best = {}  # minute -> (work, nonce)
        self.done = None  # the minute in which this address already holds a find that clears the threshold
        self.lock = threading.Lock()
        self.stats = {"submits": 0, "skips": 0, "mined": [0] * 7, "keys": 0}

    def record(self, box, nonce, chx):
        """A FOUND for this address arrived from a box: verify it and keep the best of the current minute.
        Returns True for the address's first find of the minute whose work clears the exact threshold (tq8): the tier
        is rolled at reveal, so a higher hash buys nothing and the caller stops hashing this address until the next
        minute. The caller acts on it after this returns, never under self.lock."""
        with self.lock:
            m, ch = self.cur["minute"], self.cur["ch"]
            if not ch or chx.lower() != ch.lower():
                return False  # a find for a previous challenge that arrived after the session changed
            w = work_q8(digest_of(self.account.address, nonce, chx))
            bits = w >> 8
            if bits < self.cur["floor"] - 4:
                box.strikes += 1
                log("[%s] garbage find bits=%d (floor %d) from %s" % (self.tag, bits, self.cur["floor"], box.tag))
                return False
            prev = self.best.get(m)
            if prev is None or w > prev[0]:
                self.best[m] = (w, nonce)
            if w >= self.cur["tq8"] and self.done != m:
                self.done = m
                return True
            return False

    def qualified(self, m):
        """True once this address holds a find of minute m that clears the threshold."""
        with self.lock:
            return self.done == m

    def set_session(self, m, ch, floor, tq8):
        with self.lock:
            self.cur = {"minute": m, "ch": ch, "floor": floor, "tq8": tq8}

    def settle(self, m):
        """Submit the best find of session m (called during m+1), or reveal pending finds."""
        with self.lock:
            best = self.best.pop(m, None)
        if best is None:
            self.stats["skips"] += 1
            if not self.dry and self.chain.pending(self.account.address) > 0:
                rc = self.account.reveal()
                self._log_events(rc, "reveal")
            return
        w, nonce = best
        tm = self.chain.minute_threshold(m)
        if w < tm:
            log("[%s] minute %d: best %.2f < threshold %.2f, nothing to submit" % (self.tag, m, w / 256, tm / 256))
            self.stats["skips"] += 1
            return
        if self.dry:
            log("[%s] minute %d: [dry] would submit %.2f bits nonce %d" % (self.tag, m, w / 256, nonce))
            return
        price = self.chain.price()
        value = price * 125 // 100
        h, rc = self.account.submit(m, nonce, value)
        if h is None and rc is None:  # price moved: re-quote and retry once
            value = self.chain.price() * 125 // 100
            h, rc = self.account.submit(m, nonce, value)
        if rc is False or rc is None:
            if rc is None and h:
                log("[%s] submit: no receipt (%s)" % (self.tag, h))
            return
        if rc.get("status") == "0x1":
            self.stats["submits"] += 1
            log("[%s] minute %d: submitted %.2f bits (threshold %.2f) for %.7f ETH, gas %d%s" % (self.tag, m, w / 256, tm / 256, price / 1e18, int(rc["gasUsed"], 16), self._events(rc)))
        else:
            log("[%s] submit reverted tx %s" % (self.tag, h))

    def _events(self, rc):
        extra = ""
        for l in rc.get("logs", []):
            t = l.get("topics", [])
            if t and t[0] == TOPIC_MINED and len(t) >= 4:
                tier = int(t[3], 16)
                self.stats["mined"][tier] += 1
                extra += " | revealed type %d tier %d" % (int(t[2], 16), tier)
            elif t and t[0] == TOPIC_KEY:
                self.stats["keys"] += 1
                extra += " | MYTHIC KEY"
        return extra

    def _log_events(self, rc, label):
        if rc and rc.get("status") == "0x1":
            ev = self._events(rc)
            if ev:
                log("[%s] %s:%s" % (self.tag, label, ev))

# ------------------------------------------------------------------ orchestrator
class Orchestrator:
    def __init__(self, chain, miners, box_cmds, dry, submit_delay):
        self.chain, self.miners, self.dry, self.submit_delay = chain, miners, dry, submit_delay
        self.pool = ThreadPoolExecutor(max_workers=max(2, len(miners)))
        self.by_addr = {mi.account.address.lower(): mi for mi in miners}
        self.boxes = [Box(c, miners[0].account.address, self.on_found, "box%d" % i) for i, c in enumerate(box_cmds)]
        if len(miners) > 32:
            log("WARNING: hb-miner takes at most 32 addresses per PARAMS; only the first 32 will be mined")
        # Every PARAMS broadcast (new minute, narrowing, replay after a restart) runs under plock. Lock order is
        # plock -> Miner.lock; a box reader thread holds neither when it wakes the narrower, so it never waits on them.
        self.plock = threading.Lock()
        self.session = None  # (minute, challenge, floor) the boxes are hashing
        self.sent = None  # address list of the last broadcast
        self.all_done = None  # minute already logged as fully found
        self.wake = threading.Event()
        threading.Thread(target=self.narrower, daemon=True).start()

    def on_found(self, box, addr, nonce, chx):
        """Runs on a box's reader thread. record() has released the miner's lock when it returns; the re-send itself
        happens on the narrower thread, so a slow box never stalls the reader of another."""
        mi = self.by_addr.get(addr.lower())
        if mi is not None and mi.record(box, nonce, chx):
            self.wake.set()

    def addrs(self):
        return [mi.account.address for mi in self.miners[:32]]

    def broadcast(self, ch, floor, addrs):
        """Caller holds plock."""
        self.sent = list(addrs)
        for b in self.boxes:
            b.params(ch, floor, addrs)

    def start_session(self, m, ch, floor, tq8):
        """New minute: every miner switches to it and every box gets the full address list."""
        with self.plock:
            for mi in self.miners:
                mi.set_session(m, ch, floor, tq8)
            self.session = (m, ch, floor)
            self.broadcast(ch, floor, self.addrs())

    def narrower(self):
        while True:
            self.wake.wait()
            self.wake.clear()  # a find that lands during the pass below wakes another pass
            try:
                self.narrow()
            except Exception as e:
                log("narrow error: %s" % str(e)[:160])

    def narrow(self):
        """Re-send the current minute's PARAMS (same challenge and floor) with only the addresses that have no
        qualifying find yet. With none left nothing is sent: an empty list would make hb-miner fall back to --addr,
        so the cards stay on the last list until the next minute."""
        msg = None
        with self.plock:
            if self.session is None:
                return
            m, ch, floor = self.session
            left = [mi.account.address for mi in self.miners[:32] if not mi.qualified(m)]
            if left == self.sent:
                return  # the minute changed since the wake-up, or the address was not in the list
            total = len(self.addrs())
            if left:
                self.broadcast(ch, floor, left)
                msg = "minute %d: %d/%d addresses hold a qualifying find, cards now hash the other %d" % (
                    m, total - len(left), total, len(left))
            elif self.all_done != m:
                self.all_done = m
                msg = "minute %d: all %d addresses hold a qualifying find, PARAMS unchanged until the next minute" % (m, total)
        if msg:
            log(msg)

    def keep_alive(self):
        for b in self.boxes:
            if not b.alive and b.strikes < 3 and time.time() - b.started > 10:
                b.start()
                with self.plock:  # replay the latest list, never one the narrower is about to replace
                    if b.last:
                        b.params(*b.last)

    def ensure_challenge(self, m):
        ch = self.chain.challenge(m)
        if int(ch, 16) == 0:
            if self.dry:
                log("minute %d has no challenge and --dry is on; waiting" % m)
                return None
            log("minute %d: no challenge, ticking" % m)
            self.miners[0].account.tick()
            ch = self.chain.challenge(m)
            if int(ch, 16) == 0:
                return None
        return ch

    def run(self):
        for b in self.boxes:
            b.start()
            time.sleep(0.7)  # stagger ssh connections: sshd drops bursts above MaxStartups
        stop = os.path.join(PROJ, "gpu-stop.txt")
        if os.path.exists(stop):
            os.remove(stop)
        self.chain.sync_time()
        try:
            self.chain.session = int(self.chain.view(SEL["sessionSec"]), 16) or 60
        except Exception:
            self.chain.session = 60
        log("chain clock offset %.1f s; session %ds; miners %d on %d box(es); dry=%s" % (
            self.chain.offset, self.chain.session, len(self.miners), len(self.boxes), self.dry))
        cur_minute = None
        last_settled = None
        last_report = time.time()
        while not os.path.exists(stop):
            self.chain.sync_time()
            m = self.chain.minute()
            if cur_minute != m:
                prev = cur_minute
                # the cards first: every second they keep hashing the old challenge is wasted, submits can wait
                ch = self.ensure_challenge(m)
                if ch is None:
                    time.sleep(3)
                    continue
                tq8 = self.chain.minute_threshold(m)
                # integer floor of the threshold: a hash with floor(T) leading zeros can still carry enough
                # fractional work to pass T, the exact check happens in record()/settle() against tq8
                floor = tq8 // 256
                self.start_session(m, ch, floor, tq8)
                cur_minute = m
                try:
                    log("minute %d: challenge %s.. floor %d bits (threshold %.2f), unlocked tier %d, materia %d, price %.7f ETH" % (
                        m, ch[:10], floor, tq8 / 256, self.chain.unlocked(), self.chain.ore(), self.chain.price() / 1e18))
                except Exception:
                    log("minute %d: challenge %s.. floor %d bits" % (m, ch[:10], floor))
                if prev is not None and prev != last_settled:
                    delay = min(self.submit_delay, self.chain.session / 5)
                    time.sleep(max(0, delay - (self.chain.now() - m * self.chain.session)))
                    futures = [self.pool.submit(mi.settle, prev) for mi in self.miners]
                    for f in futures:
                        try:
                            f.result()
                        except Exception as e:
                            log("settle error: %s" % str(e)[:160])
                    last_settled = prev
            self.keep_alive()
            if time.time() - last_report > 600:
                last_report = time.time()
                tot = [sum(mi.stats["mined"][t] for mi in self.miners) for t in range(1, 6)]
                log("REPORT submits %d skips %d tiers C/U/R/E/L %s keys %d | boxes %s" % (
                    sum(mi.stats["submits"] for mi in self.miners), sum(mi.stats["skips"] for mi in self.miners), "/".join(map(str, tot)), sum(mi.stats["keys"] for mi in self.miners),
                    " ".join("%s=%.2fGH/s" % (b.tag, b.rate) for b in self.boxes)))
            time.sleep(1)
        for b in self.boxes:
            b.quit()
        log("stopped")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--net", default=os.environ.get("NET", "robinhood"))
    ap.add_argument("--box", action="append", required=True, help="command that launches hb-miner (--addr/--persist are appended); repeat for several cards")
    ap.add_argument("--miners-file", help="file with one private key per line; each key gets its own process per --box")
    ap.add_argument("--dry", action="store_true", help="never send transactions")
    ap.add_argument("--submit-delay", type=float, default=4.0, help="seconds into the next session before submitting")
    ap.add_argument("--deployment", help="deployment JSON (default deployments/<net>.json next to the program)")
    ap.add_argument("--rpc", help="RPC URL (default from .env or the public endpoint of --net)")
    a = ap.parse_args()
    env = load_env()
    dep = json.load(open(a.deployment or os.path.join(PROJ, "deployments", "%s.json" % a.net), encoding="utf-8"))
    default_rpc = {"robinhood": "https://robinhood-rpc.publicnode.com", "robinhoodTestnet": "https://rpc.testnet.chain.robinhood.com/rpc", "localhost": "http://127.0.0.1:8545"}.get(a.net)
    rpc_url = a.rpc or env.get("RPC_URL") or (env.get("ROBINHOOD_RPC") if a.net == "robinhood" else env.get("ROBINHOOD_TESTNET_RPC") if a.net == "robinhoodTestnet" else None) or default_rpc
    chain = Chain(Rpc(rpc_url), dep["chainId"], dep["contracts"]["Mine"])
    if a.miners_file:
        keys = [l.strip() for l in open(a.miners_file, encoding="utf-8") if l.strip().startswith("0x")]
    else:
        keys = [env.get("MINER_KEY") or env.get("DEPLOYER_KEY")]
    miners = [Miner(i, Account_(chain, k), chain, a.dry) for i, k in enumerate(keys)]
    Orchestrator(chain, miners, a.box, a.dry, a.submit_delay).run()

if __name__ == "__main__":
    main()
