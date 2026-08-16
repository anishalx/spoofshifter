# SpoofShifter

**SpoofShifter** is an advanced DNS spoofing tool for ethical hackers and
penetration testers. Written in Python on top of `Scapy` and
`NetfilterQueue`, it intercepts DNS traffic and forges responses, redirecting
victims to an address of your choosing. Combined with the built-in ARP
spoofer, it performs full man-in-the-middle (MitM) sessions on its own.

> ⚠️ **Authorized use only.** Only run this against networks and systems you
> own or have explicit permission to test. See the [Disclaimer](#disclaimer).

## Features

- **Multiple spoofing rules** with wildcard support (`*.example.com`) and
  per-domain IPv4 **and** IPv6 addresses.
- **Two interception modes:**
  - `reply` (default) – answers DNS *queries* with forged responses; the
    most reliable mode, works even after the real response was forwarded.
  - `mutate` – rewrites DNS *responses* in transit (original behaviour),
    hardened for TCP: only segments carrying one complete DNS message are
    rewritten, and only when the rewrite preserves the segment length (so
    TCP sequence/ACK accounting is never corrupted). Fragmented packets are
    never modified.
- **Passive recon mode** – `--list-domains` logs every DNS query (name,
  type, client) and forwards it untouched; useful for mapping a target's
  traffic before an engagement, with no spoofing rules required. Pair it
  with `--top-domains` to print the most-queried domains on exit.
- **Automatic iptables management** – installs and removes exactly the
  NFQUEUE rules it needs (never flushes your other rules). `nat`-table
  (router) mode supported.
- **Built-in ARP spoofing** – no second tool needed for a full MitM session;
  restores ARP tables and IP forwarding on exit.
- **Graceful shutdown** – Ctrl-C / SIGTERM unbinds the queue, removes the
  firewall rules, restores ARP and IP forwarding.
- **Config files** (JSON) – CLI flags override file values.
- **Robust** – malformed packets are passed through instead of crashing the
  loop; per-packet error handling; packet statistics on exit.
- **Tested** – 164 unit tests covering the engine (including TCP DNS
  mutation, fragment handling, the recon mode and query ranking), firewall
  helpers, ARP spoofer, config loading, the runner, the systemd unit and the
  packaging metadata (runs on any platform).

## Requirements

Linux (packet capture uses `NFQUEUE`), Python 3.8+, root.

```bash
sudo apt-get update
sudo apt-get install libnetfilter-queue-dev iptables
pip install -r requirements.txt
```

## Installation

Install from the repository (Linux recommended; the test-suite runs anywhere):

```bash
pip install .                 # installs the `spoofshifter` command
pip install -e .              # editable install for development
pip install -e '.[dev]'       # + pytest for the test-suite
```

This installs a `spoofshifter` console command (equivalent to running
`spoofshifter.py` from a checkout). The `netfilterqueue` dependency is
Linux-only and is skipped automatically on other platforms. To run from a
checkout without installing, use `sudo python3 spoofshifter.py` directly.

## Usage

```bash
sudo spoofshifter -d www.google.com@10.0.2.4
```

or from a checkout:

```bash
sudo python3 spoofshifter.py -d www.google.com@10.0.2.4
```

Spoof several domains, including wildcards and IPv6:

```bash
sudo python3 spoofshifter.py \
    -d 'www.google.com@10.0.2.4' \
    -d '*.example.com@10.0.2.4' \
    -d 'ipv6.example.com@[fd00::1]'
```

Run a full MitM session with ARP spoofing built in:

```bash
sudo python3 spoofshifter.py -d '*.example.com@10.0.2.4' \
    --arp-spoof --target 192.168.1.100 --gateway 192.168.1.1 -i eth0
```

Use a config file (see [`config.example.json`](config.example.json)):

```bash
sudo python3 spoofshifter.py -c config.json
```

Passively log all DNS queries without spoofing anything (no rules needed),
and get a ranked list of the most-queried domains when the session ends:

```bash
sudo python3 spoofshifter.py --list-domains --top-domains
sudo python3 spoofshifter.py --list-domains --top-domains 25   # top 25
```

### Options

| Flag | Description |
| --- | --- |
| `-d, --domain DOMAIN[@IP]` | Rule to spoof; repeatable. `example.com@10.0.2.4`, `*.example.com@[fd00::1]`, or bare `example.com` with `--ip`. |
| `--ip IP` | Default spoof address for bare domains. |
| `-c, --config FILE` | JSON config file (CLI flags override it). |
| `-q, --queue NUM` | NFQUEUE number (default `0`). |
| `--mode {reply,mutate,listen}` | Interception mode (default `reply`; `listen` is the same as `--list-domains`). |
| `--list-domains` | Passive recon: log every DNS query and forward it untouched. |
| `--top-domains [N]` | Print the most-queried domains (ranked by count) on exit; default top 10. |
| `--ttl SEC` | TTL on forged answers (default `300`). |
| `--no-iptables` | Don't touch iptables (rules already set up). |
| `--nat` | Hook `nat` PREROUTING/OUTPUT (router mode) instead of FORWARD/OUTPUT. |
| `--no-bypass` | Drop DNS while the tool is stopped instead of using `--queue-bypass`. |
| `--arp-spoof` | Also run ARP spoofing (needs `--target`, `--gateway`, `-i`). |
| `--target IP` | Victim IP for ARP spoofing. |
| `--gateway IP` | Gateway/router IP for ARP spoofing. |
| `-i, --iface IFACE` | Network interface for ARP spoofing. |
| `--arp-interval SEC` | Seconds between ARP poison packets (default `2`). |
| `-v, --verbose` | Debug logging. |
| `--quiet` | Only log errors. |

### Manual iptables (if you prefer)

```bash
# Redirect DNS to the queue yourself, then run with --no-iptables
sudo iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0 --queue-bypass
sudo python3 spoofshifter.py -d www.google.com@10.0.2.4 --no-iptables
# Clean up your own rules afterwards
sudo iptables -D FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0 --queue-bypass
```

## How it works

1. **Interception** – iptables sends DNS traffic (UDP/TCP port 53) to an
   NFQUEUE, which SpoofShifter reads with `NetfilterQueue`.
2. **Matching** – each DNS query's name is matched (case-insensitively,
   trailing-dot aware) against your rules: exact names and `*.` wildcards;
   the most specific rule wins.
3. **Forgery** – in `reply` mode a forged response is crafted that echoes the
   query's transaction id and ports, swaps the source/destination addresses,
   and carries your spoofed A/AAAA record. AAAA queries for IPv4-only rules
   are dropped so the client falls back to IPv4. Lengths and checksums are
   recalculated on serialization.
4. **Safe rewriting** – fragmented IP packets are never modified (a length
   change would break reassembly). In `mutate` mode, TCP responses are only
   rewritten when the segment holds exactly one complete DNS message (not
   split or coalesced) **and** the new answer keeps the segment the same
   length, so the TCP stream stays consistent; otherwise they are forwarded
   untouched.
5. **Cleanup** – on exit the firewall rules added by the tool are removed one
   by one, ARP tables and IP forwarding are restored, and a packet summary is
   printed.

## Run as a persistent systemd service

Install SpoofShifter under `/opt`, point the service at a config file, and let
systemd keep it alive:

```bash
# 1. Install under /opt (or clone the repo there)
sudo cp -r . /opt/spoofshifter
cd /opt/spoofshifter && sudo pip install -r requirements.txt

# 2. Create and edit the config file (see config.example.json)
sudo mkdir -p /etc/spoofshifter
sudo cp config.example.json /etc/spoofshifter/config.json
sudo nano /etc/spoofshifter/config.json

# 3. Install the unit (adjust ExecStart to your install: either the pip
#    binary `/usr/local/bin/spoofshifter` or a checkout + venv interpreter)
sudo cp systemd/spoofshifter.service /etc/systemd/system/
sudo systemctl daemon-reload

# 4. Enable and start
sudo systemctl enable --now spoofshifter

# 5. Verify
systemctl status spoofshifter
journalctl -u spoofshifter -f        # live spoofing logs
```

Notes:
- The service runs as root (required for NFQUEUE/iptables/ARP) but is
  sandboxed with `ProtectSystem=strict`, `ProtectHome` and a private `/tmp`.
- On stop, systemd sends SIGTERM; SpoofShifter's cleanup removes the iptables
  rules it installed and restores ARP state before exiting.
- If the process is killed with SIGKILL the firewall rules stay behind; on the
  next start remove stale rules with `sudo iptables -t filter -L FORWARD -n --line-numbers`.

## Development

Run the test suite (works on any platform – no root or NFQUEUE needed):

```bash
python -m venv .venv
.venv/Scripts/pip install scapy pytest     # or .venv/bin/pip on Linux
.venv/Scripts/python -m pytest
```

## Project layout

```
spoofshifter.py        # thin entry point (run with sudo)
spoofshifter/
  core.py              # DNS engine: matching, forgery, packet processing
  config.py            # CLI parsing + JSON config files
  firewall.py          # iptables/ip6tables rule management
  arp.py               # ARP spoofing companion + IP forwarding
  runner.py            # NetfilterQueue binding and lifecycle
  cli.py               # wiring, banner, cleanup
tests/                 # 164 unit tests
systemd/               # spoofshifter.service unit file
config.example.json    # sample config file
```

## Disclaimer

This tool is intended for educational purposes and authorized penetration
testing only. Do not use it on networks without proper authorization. The
developers are not responsible for any misuse of this tool.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE)
file for more details.
