# file2air-python

A Python/[Scapy](https://scapy.net/) port of Joshua Wright's
[file2air](https://www.willhackforsushi.com/) v1.1 (2005).

The original tool injects a single 802.11 frame, read from a binary file, onto
a wireless network — letting you override addresses, sequence numbers, and
fragment the payload before transmission. It relied on LORCON for low-level
injection, which in turn required patched, now-outdated wireless drivers.
This port swaps LORCON out for Scapy + RadioTap so injection works on any
modern Linux mac80211 interface in monitor mode, no out-of-tree kernel
patches required.

> **Authorized use only.** This tool injects arbitrary 802.11 frames and can
> disrupt nearby wireless networks and devices. Run it only against equipment
> you own or have explicit written permission to test. Follow local regulatory
> rules for radio transmission. The author and the original authors take no
> responsibility for misuse.

---

## About the original tool

`file2air` was written by **Joshua Wright** (`<jwright@hasborg.com>`) in 2005,
based on FX's earlier `file2wire`. Josh is a long-time wireless and IoT
security researcher, SANS Senior Instructor, co-author of *Hacking Exposed
Wireless*, and author of a string of well-known wireless tools — `asleap`,
`cowpatty`, `coWPAtty`, `pyrit`-era contributions, and many others — that
shaped a generation of Wi-Fi security testing.

This port exists because file2air is still genuinely useful for crafted-frame
work (CTFs, classroom labs, fuzzing wireless stacks, reproducing CVEs), but
the LORCON dependency makes it painful to get running on a current Linux
system. Scapy already speaks RadioTap and is `pip`-installable, so the port
is mostly mechanical — every CLI flag and behavior from Josh's v1.1 is
preserved.

All credit for the design, the CLI surface, the sample packets, and the
fragmentation logic goes to Josh. Credit for the original `file2wire` that
inspired it goes to **FX** (`<fx@phenoelit.de>`) of Phenoelit.

---

## Requirements

| Dependency | Why | How to get it |
| --- | --- | --- |
| Python 3.8+ | Runtime | distro package or [python.org](https://www.python.org/) |
| Scapy ≥ 2.5 | Raw 802.11 + RadioTap injection | `pip install scapy` |
| libpcap | Scapy's L2 backend on most systems | distro package |
| `iw` | Channel switching via `-c/--channel` | distro package |
| Linux mac80211 driver with monitor-mode support | Actual injection | already in-tree for most modern Wi-Fi chipsets |
| Root or `CAP_NET_RAW` | Raw socket creation | `sudo` or `setcap` |

`aircrack-ng` is not required but bundles handy helpers (`airmon-ng`) for
flipping an interface into monitor mode.

### Install on Debian / Ubuntu / Kali

```sh
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libpcap-dev iw aircrack-ng
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Install on Fedora / RHEL / CentOS Stream

```sh
sudo dnf install -y python3 python3-pip libpcap-devel iw aircrack-ng
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Install on Arch / Manjaro

```sh
sudo pacman -S --needed python python-pip libpcap iw aircrack-ng
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Grant raw-socket access without `sudo`

```sh
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

(Granting `CAP_NET_RAW` to your system Python is a blunt instrument — prefer a
venv interpreter, and revoke with `sudo setcap -r ...` when done.)

---

## Setting up monitor mode

`file2air-python` requires a wireless interface already in monitor mode. The
easiest path:

```sh
# Identify your wireless interface
ip link

# Take it down, switch to monitor, bring it back up
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Or with airmon-ng (creates wlan0mon)
sudo airmon-ng check kill          # stop NetworkManager/wpa_supplicant first
sudo airmon-ng start wlan0
```

Confirm with `iw dev` — the `type` should read `monitor`.

To set a specific channel:

```sh
sudo iw dev wlan0mon set channel 6
```

(or let `file2air-python -c 6` do it for you).

---

## Usage

```
file2air-python [options]

  -i, --interface IFACE   Wireless monitor-mode interface (required)
  -f, --filename PATH     Binary 802.11 frame to inject (required)
  -r, --driver NAME       Driver name (LORCON-era compat shim; ignored)

  -c, --channel N         Switch the interface to channel N before sending
  -n, --count N           Number of times to send the frame (default 1)
  -w, --delay SPEC        Inter-packet delay. `uX` = X microseconds,
                          `X` = X seconds. (e.g. `u250000` or `1`)
  -t, --fast              Alias for `-w u100000` (10 packets/sec)

  -d, --dest MAC          Override addr1 (destination)
  -s, --source MAC        Override addr2 (source)
  -b, --bssid MAC         Override addr3 (BSSID)
  -a, --wds MAC           Override addr4 (WDS / 4-address frames only)
  -q, --seqnum N          Set the sequence number (0x-prefix for hex, max 4095)
  -Q, --seqnuminc N       Set the sequence number and increment per packet
  -p, --pieces N          Fragment the payload into N pieces

  -h, --help              Show help and exit
  -v, --verbose           Verbose output (repeat for more)
```

### Producing input files

Open a capture in Wireshark, select the frame you want to clone, then
**File → Export Packet Bytes…** and save as a `.bin`. The `packets/` directory
ships with the originals from Josh's release (deauth, disassoc, probe-resp,
ack, cts, rts, several EAPOL variants, and the KoreK WEP injection frame).

### Examples

**Replay a deauth frame at one client, once:**

```sh
sudo python3 file2air.py -i wlan0mon \
    -d 00:01:02:03:04:05 \
    -s 00:40:96:01:02:03 \
    -b 00:40:96:01:02:03 \
    -f ./packets/deauth.bin
```

(`-d` is the victim STA, `-s`/`-b` is the AP it was associated with.)

**Broadcast deauth flood, 65k packets, default rate:**

```sh
sudo python3 file2air.py -i wlan0mon -n 65000 \
    -d ff:ff:ff:ff:ff:ff \
    -s 00:40:96:01:02:03 \
    -b 00:40:96:01:02:03 \
    -f ./packets/deauth.bin
```

**Rogue probe-response storm at 10 pps with sequential sequence numbers
starting at 0x100, on channel 6:**

```sh
sudo python3 file2air.py -i wlan0mon -c 6 -t -n 500 -Q 0x100 \
    -d ff:ff:ff:ff:ff:ff \
    -f ./packets/proberesp.bin
```

**Fragment a payload across 4 fragments (tests fragmentation reassembly on
the receiver):**

```sh
sudo python3 file2air.py -i wlan0mon -p 4 -f ./packets/somethingclever-beacon.bin
```

**Inject a 4-address (WDS) frame and set the addr4 field explicitly:**

```sh
sudo python3 file2air.py -i wlan0mon \
    -a 00:11:22:33:44:55 \
    -f ./my-4addr-frame.bin
```

**The classic loop from Josh's original README — alternating deauth bursts
and rogue probe responses:**

```sh
sudo /bin/bash -c 'while : ; do
    python3 file2air.py -i wlan0mon -n 3 -d ff:ff:ff:ff:ff:ff \
        -s 00:40:96:01:02:03 -b 00:40:96:01:02:03 \
        -f ./packets/deauth.bin
    python3 file2air.py -i wlan0mon -n 100 -d ff:ff:ff:ff:ff:ff \
        -s 00:40:96:01:02:03 -b 00:40:96:01:02:03 \
        -f ./packets/proberesp.bin
done'
```

### Verbose output

`-v` prints a hexdump of the frame after overrides are applied (matching the
original tool's `lamont_hdump` layout). `-vv` additionally enables Scapy's
own per-packet send logging.

---

## What changed vs. the C version

- **Injection backend**: Scapy + a bare RadioTap header rather than LORCON.
  Works on any in-tree mac80211 driver in monitor mode.
- **`-r/--driver`**: parsed and ignored. Kept for command-line compatibility
  with scripts/notes written against Josh's tool. (Scapy doesn't need a
  per-driver shim.)
- **`-c/--channel`**: shells out to `iw dev <iface> set channel <n>`. The C
  version called `tx80211_setchannel` directly through LORCON.
- **`-a/--wds` bugfix**: the original C source had
  `strncpy(opt_bssid, optarg, sizeof(opt_wds)-1)` for the `-a` handler,
  which silently overwrote the BSSID buffer. The port stores `args.wds`
  separately from `args.bssid`.
- **Errors**: clean `error: ...` messages, no Python tracebacks bleeding
  through on common failures (missing interface, permission denied, etc.).

Everything else — the CLI surface, sequence-number arithmetic, fragment
splitting, the `uX`/`X` delay grammar, the `-t` alias, the per-iteration
sequence increment with 4095 wrap — is intentionally identical to v1.1.

---

## Troubleshooting

- **`error: permission denied opening raw socket`** — run with `sudo` or
  grant `CAP_NET_RAW` to your interpreter.
- **`BIOCSETIF failed on …` / `No such device`** — the interface name is
  wrong or the interface is not up. Check with `ip link` / `iw dev`.
- **Frames "send" but nothing shows in a sniffer** — interface is probably
  not in monitor mode, or it's on a different channel. Verify with
  `iw dev`, and use a second adapter in monitor mode to capture.
- **Channel set fails with "command failed: Device or resource busy"** —
  NetworkManager or wpa_supplicant is still touching the radio. Stop them
  (`sudo airmon-ng check kill`) and retry.
- **Driver claims to support monitor but injection is silent** — some
  chipsets (notably certain Realtek and Broadcom parts) need a
  reverse-engineered or out-of-tree driver to inject. Atheros (`ath9k_htc`,
  `ath9k`) and Mediatek (`mt76`) chipsets are the most reliable choices.

---

## License

GPL v2, matching the original. See [`LICENSE`](./LICENSE).

## Credits

- **Joshua Wright** (`<jwright@hasborg.com>`) — original `file2air` (2005),
  the CLI design, the sample packets, and the fragmentation/sequence
  semantics this port faithfully preserves.
  Website: <https://www.willhackforsushi.com/>
- **FX** (`<fx@phenoelit.de>`) and **Phenoelit** — `file2wire` (2001), the
  ancestor that `file2air` was derived from.
- **Dragorn** — credited by Josh in the original README for endless C help.
- **Larry Pesce** — this Python/Scapy port.
