#!/bin/bash
# SpoofShifter live end-to-end self-test.
#
# Run on a Linux box as root:
#     sudo ./tools/self_test.sh
#
# What it does (all through the real kernel path - iptables, NFQUEUE, real
# UDP sockets):
#   1. listen mode observes a genuine DNS query and forwards it untouched
#   2. reply mode answers a genuine DNS query with a forged A record, which
#      the test client receives and validates (id echo + rdata)
#   3. recon mode aggregates --top-domains and prints the ranking on exit
#   4. every run is stopped with SIGTERM and the script verifies the tool
#      removed its own iptables rules and exited cleanly
#
# The "resolver" address 192.0.2.1 (TEST-NET-1) is never actually contacted:
# in reply mode the tool answers and drops the query, so the test needs no
# internet access. Nothing outside the NFQUEUE rules the tool installs is
# touched, and the trap cleans those up even on failure.
#
# Exit status is non-zero if any check fails.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="python3"
command -v "$PYTHON" >/dev/null 2>&1 || PYTHON="python"

SERVER="192.0.2.1"      # TEST-NET-1: never reached, no internet needed
PASS=0
FAIL=0
TOOL_PID=""

say()  { printf '%s\n' "$*"; }
ok()   { say "  [PASS] $*"; PASS=$((PASS + 1)); }
bad()  { say "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
step() { say ""; say "=== $* ==="; }
die()  { say "[-] $*"; exit 1; }

# --- environment checks ----------------------------------------------------
[[ $EUID -eq 0 ]] || die "Run as root: sudo $0"
command -v iptables >/dev/null 2>&1 || die "'iptables' is required on this system."
"$PYTHON" -c "import scapy, netfilterqueue" 2>/dev/null \
    || die "install the tool's dependencies first: pip install scapy netfilterqueue"

# Locate the tool: the installed 'spoofshifter' command, or spoofshifter.py
# from a checkout.
TOOL_CMD=""
if command -v spoofshifter >/dev/null 2>&1; then
    TOOL_CMD="spoofshifter"
elif [[ -f "$SCRIPT_DIR/../spoofshifter.py" ]]; then
    TOOL_CMD="$PYTHON $SCRIPT_DIR/../spoofshifter.py"
else
    die "cannot find the 'spoofshifter' command or spoofshifter.py"
fi
say "using: $TOOL_CMD"

# --- helpers ---------------------------------------------------------------
# start_tool <logfile> <args...>
start_tool() {
    local log="$1"; shift
    "$TOOL_CMD" "$@" >"$log" 2>&1 &
    TOOL_PID=$!
}

# wait_ready <logfile> <queue-num>  -> 0 when the tool is bound to the queue
wait_ready() {
    local log="$1" queue="$2" i
    for i in $(seq 1 30); do
        grep -q "bound to NFQUEUE $queue" "$log" && return 0
        grep -q "error:" "$log" && return 1
        sleep 0.2
    done
    return 1
}

# stop_tool <logfile> <expected-exit-code>  -> verifies graceful shutdown
stop_tool() {
    local log="$1" want="${2:-0}" rc
    kill -TERM "$TOOL_PID" 2>/dev/null
    wait "$TOOL_PID" 2>/dev/null
    rc=$?
    [[ $rc -eq $want ]] && ok "tool exited with code $rc on SIGTERM" \
                        || bad "tool exit code was $rc, expected $want"
    grep -q "iptables rules removed" "$log" \
        && ok "iptables rules removed on shutdown" \
        || bad "iptables rules were not removed on shutdown"
    grep -q "summary:" "$log" \
        && ok "packet summary printed" \
        || bad "no packet summary in the output"
    TOOL_PID=""
}

# check_no_rules -> verifies no NFQUEUE port-53 rules remain in FORWARD/OUTPUT
check_no_rules() {
    if iptables -t filter -S FORWARD 2>/dev/null | grep -q NFQUEUE || \
       iptables -t filter -S OUTPUT 2>/dev/null | grep -q NFQUEUE; then
        bad "NFQUEUE rules still present after shutdown"
    else
        ok "no NFQUEUE rules left in FORWARD/OUTPUT"
    fi
}

# send_query <logfile> <queue-num> <name>  -> sends one DNS query via UDP
send_query() {
    local log="$1" queue="$2" name="$3"
    "$PYTHON" - send "$SERVER" "$name" <<'PYEOF' || bad "failed to send query for $name"
import socket, struct, sys

def build_query(name, tid):
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)

name = sys.argv[2]
tid = 0x4A11
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(build_query(name, tid), (sys.argv[1], 53))
print("sent query for %s to %s" % (name, sys.argv[1]))
PYEOF
}

# expect_answer <name> <expected-ip> -> sends a query and validates the reply
expect_answer() {
    local name="$1" expected="$2"
    "$PYTHON" - expect "$SERVER" "$name" "$expected" <<'PYEOF'
import socket, struct, sys

def build_query(name, tid):
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)

name, expected = sys.argv[2], sys.argv[3]
tid = 0x4A11
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5.0)
sock.sendto(build_query(name, tid), (sys.argv[1], 53))
try:
    data, _ = sock.recvfrom(4096)
except socket.timeout:
    print("FAIL: no response received within timeout"); sys.exit(1)
from scapy.layers.dns import DNS
dns = DNS(data)
if dns.id != tid:
    print("FAIL: transaction id %04x != %04x" % (dns.id, tid)); sys.exit(1)
answers = [r.rdata for r in (dns.an or []) if getattr(r, "type", None) == 1]
if not answers:
    print("FAIL: no A record in the answer"); sys.exit(1)
if answers[0] != expected:
    print("FAIL: got %s, expected %s" % (answers[0], expected)); sys.exit(1)
print("OK: %s -> %s (id %04x)" % (name, answers[0], tid))
PYEOF
}

# --- cleanup (safety net; graceful shutdown should have done all of this) ---
cleanup() {
    [[ -n "$TOOL_PID" ]] && kill -9 "$TOOL_PID" 2>/dev/null
    for q in 1 2 3; do
        for chain in FORWARD OUTPUT; do
            for proto in udp tcp; do
                iptables -t filter -D "$chain" -p "$proto" --dport 53 \
                    -j NFQUEUE --queue-num "$q" --queue-bypass 2>/dev/null
            done
        done
    done
    say ""
    say "==== $PASS passed, $FAIL failed ===="
    [[ $FAIL -eq 0 ]]
}
trap cleanup EXIT

# --- 1. listen mode observes a real query ----------------------------------
step "Test 1 - listen mode observes a genuine DNS query"
L1="$(mktemp)"
start_tool "$L1" --list-domains --queue 1
if wait_ready "$L1" 1; then
    ok "tool bound to NFQUEUE 1"
    send_query "$L1" 1 "test1.example.com"
    sleep 0.5
    grep -q "query test1.example.com (A) from" "$L1" \
        && ok "query for test1.example.com was logged" \
        || bad "query was not logged (see $L1)"
else
    bad "tool did not bind NFQUEUE 1 (see $L1)"
fi
stop_tool "$L1" 0
check_no_rules
rm -f "$L1"

# --- 2. reply mode forges the answer ---------------------------------------
step "Test 2 - reply mode answers a genuine query with a forged A record"
L2="$(mktemp)"
start_tool "$L2" -d "test2.example.com@10.9.9.9" --queue 2
if wait_ready "$L2" 2; then
    ok "tool bound to NFQUEUE 2"
    if expect_answer "test2.example.com" "10.9.9.9"; then
        ok "client received the forged A record 10.9.9.9"
    else
        bad "client did not receive the forged answer"
    fi
    grep -q "spoofing test2.example.com A -> 10.9.9.9" "$L2" \
        && ok "spoofing event was logged" || bad "no spoofing event in the log"
else
    bad "tool did not bind NFQUEUE 2 (see $L2)"
fi
stop_tool "$L2" 0
check_no_rules
rm -f "$L2"

# --- 3. --top-domains aggregation ------------------------------------------
step "Test 3 - --top-domains ranks the observed queries on exit"
L3="$(mktemp)"
start_tool "$L3" --list-domains --top-domains 5 --queue 3
if wait_ready "$L3" 3; then
    ok "tool bound to NFQUEUE 3"
    send_query "$L3" 3 "rank1.example.com"
    send_query "$L3" 3 "rank1.example.com"
    send_query "$L3" 3 "rank2.example.com"
    sleep 0.5
    kill -TERM "$TOOL_PID" 2>/dev/null
    wait "$TOOL_PID" 2>/dev/null
    TOOL_PID=""
    grep -q "top domains" "$L3" \
        && ok "top-domains report printed" || bad "no top-domains report (see $L3)"
    grep -q "rank1.example.com" "$L3" \
        && ok "rank1.example.com appears in the report" || bad "missing ranked domain"
    grep -q "iptables rules removed" "$L3" \
        && ok "iptables rules removed on shutdown" || bad "rules not removed"
    check_no_rules
else
    bad "tool did not bind NFQUEUE 3 (see $L3)"
fi
rm -f "$L3"

say ""
say "All live end-to-end checks finished."
