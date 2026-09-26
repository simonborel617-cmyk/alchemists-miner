# Alchemists miner

Standalone GPU miner for the [Alchemists](https://github.com/simonborel617-cmyk/alchemists) mine on Robinhood Chain: proof-of-work
mining of alchemical ingredients. Most players mine straight from the game's website (CPU or WebGPU, no install). This repository is
for rigs and rented cards: it is faster per card, runs unattended and drives up to 32 addresses per card.

Two parts:

| Part | Runs on | Does |
|---|---|---|
| `miner/hb-miner.cu` → `hb-miner-linux-x64` | Linux + NVIDIA (Turing, Ampere, Ada, Hopper; CUDA driver 12.4+) | SHA-256 for up to 32 addresses per card, one process |
| `orchestrator/gpu-miner.py` → `alchemists-miner.exe` | Windows or any Python 3.10+ machine, keys stay here | sessions, submits, reveals, reports |

The card can live on another machine or in the cloud: the orchestrator talks to it over ssh and only ever sends public addresses.

## How it works

Every minute the mine issues a new challenge and a threshold in bits. The orchestrator sends the card one line,
`PARAMS <challenge> <threshold> <addr1,addr2,...>`, and a single miner process hashes `sha256(address ‖ nonce ‖ challenge)`
for all addresses in turn. When it finds a hash above the threshold for an address it prints
`FOUND addr=... nonce_dec=... challenge=... bits=N`, and the orchestrator takes that address off the card's list for the
rest of the minute, so the card's full power goes to the addresses that still have nothing. In the next minute the
orchestrator submits the find of every address and pays the current submit price in ETH. How far above the threshold
the hash lands does not matter: the type and tier of the ingredient are rolled at the reveal one minute later, with the
same odds for every find, so a higher hash buys nothing. The next submit does the reveal.

One address can submit one find per minute, so a strong card is split across several addresses. They share one process,
so the card's power is divided between them without loss. Every 10 seconds the miner prints `STATS ... rate=` in GH/s.

## Install

Releases carry `hb-miner-linux-x64`, `alchemists-miner.exe` and `SHA256SUMS`. Verify the checksums before running anything.

Build the hasher yourself on a CUDA devel box (any `nvidia/cuda:12.x-devel` image works):

```bash
nvcc -O3 -arch=sm_86 miner/hb-miner.cu -o hb-miner        # your card's arch, or miner/build-dist.sh for the fat binary
./hb-miner --selftest                                      # expect SELF-TEST: PASS and SELF-TEST host: PASS
./hb-miner --addr 0x1111111111111111111111111111111111111111 \
  --challenge 0x4242424242424242424242424242424242424242424242424242424242424242 --benchsecs 20
```

Run the orchestrator from source instead of the exe:

```bash
pip install -r requirements.txt
python orchestrator/gpu-miner.py --help
```

## Run

1. One private key per line in `miners.txt`. Each address needs ETH for gas and for the submit price (0.0002 ETH at the start, rising with mining).
2. Put `deployments/<network>.json` next to the orchestrator: the contract addresses of the network you mine (`robinhood.json`, Robinhood Chain mainnet, is included in the release).
3. A card over ssh, all addresses from `miners.txt`:

```bash
alchemists-miner.exe --net robinhood --box "ssh -i C:/path/key -p PORT root@HOST ./hb-miner-linux-x64" --miners-file miners.txt
```

A local card under Linux:

```bash
python orchestrator/gpu-miner.py --net robinhood --box "./hb-miner-linux-x64" --miners-file miners.txt
```

Several cards: repeat `--box` for each one, every address goes to every card. Dry run without transactions: `--dry`.
Stop: create a file named `gpu-stop.txt` next to the program. Custom RPC: `--rpc URL`.

You will see one line per minute with the challenge, threshold, unlocked tiers, prima materia left and price, and a line
`submitted N bits ... revealed type T tier K` for every submit. If the best hash of the minute is below the threshold
there is no submit and nothing is spent. Every ten minutes a report by tier and the hashrate of every card.

## Costs and safety

Gas is about 300k per submit with reveal; at a 0.01 gwei base fee that is thousandths of a cent. The main cost is the
submit price, which goes to the game's treasury. The orchestrator pays with a 25 % margin and the contract refunds the
excess in the same transaction.

Keys never leave the machine that runs the orchestrator. Do not run the orchestrator on a rented card.

## Protocol reference

`hb-miner --persist` reads lines from stdin and writes lines to stdout:

- `PARAMS <challenge> <floor> [addr1,addr2,...]` starts a session; without an address list the `--addr` address is used.
- `QUIT` exits.
- `FOUND addr=0x.. nonce_dec=.. challenge=0x.. bits=N`: a hash with `N` leading zero bits; in multi-address mode the
  miner raises that address's floor to `N+1` on its own. Once the find clears the minute's exact threshold, the
  orchestrator re-sends `PARAMS` for the same challenge and floor without that address (every `PARAMS` restarts from a
  fresh random nonce base); when no address is left it sends nothing until the next minute.
- `STATS hashes=.. secs=.. rate=..` every 10 s, exact: a kernel launch never exits early, it returns its best hash.

`orchestrator/fake-hb-miner.py` speaks the same protocol on the CPU for tests without a GPU.
