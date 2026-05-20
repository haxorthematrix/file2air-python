# file2air-python

A Python port of Joshua Wright's [file2air](https://www.willhackforsushi.com/?page_id=19) v1.1
(2005). The original tool depended on LORCON for raw 802.11 injection through a
set of patched, now-outdated wireless drivers. This port replaces LORCON with
[Scapy](https://scapy.net/), so injection works on any modern Linux mac80211
interface in monitor mode without out-of-tree driver patches.

> file2air reads a binary input file containing a single 802.11 frame and
> transmits the contents onto a wireless network. Command-line options
> override the destination, source, and BSSID addresses, sequence number, and
> other fields; the user can also specify a packet count and an arbitrary
> delay between packets.

For authorized security testing, CTFs, lab work, and research only. The user
is responsible for compliance with all applicable laws and policies.

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/) (`pip install scapy`)
- A wireless interface in monitor mode (Linux mac80211)
- `iw` in `$PATH` if you want `-c/--channel` to switch channels
- Root or `CAP_NET_RAW` capability for raw socket injection

## Install

```sh
git clone <this-repo> file2air-python
cd file2air-python
pip install -r requirements.txt
```

## Usage

```
file2air-python [options]

  -i  --interface       Wireless monitor-mode interface
  -r  --driver          Driver name (LORCON-era compatibility shim; ignored)
  -f  --filename        Binary 802.11 frame to inject

  -c  --channel         Channel number
  -n  --count           Number of packets to send
  -w  --delay           Delay between packets (uX for usec, X for sec)
  -t  --fast            Alias for -w u100000 (10 packets/sec)

  -d  --dest            Override the destination address (addr1)
  -s  --source          Override the source address (addr2)
  -b  --bssid           Override the BSSID address (addr3)
  -a  --wds             Override the WDS address (addr4, 4-addr frames)
  -q  --seqnum          Override the sequence number (0x prefix for hex)
  -Q  --seqnuminc       Override the sequence number and increment per packet
  -p  --pieces          Fragment the payload into N pieces

  -h  --help            Show this help and exit
  -v  --verbose         Verbose output (repeat for more)
```

## Differences from the C version

- **Injection backend**: Scapy + RadioTap instead of LORCON. Works on stock
  Linux mac80211 drivers; no patched kernel modules required.
- **`-r/--driver`**: accepted for CLI compatibility but ignored. Scapy does
  not need a per-driver shim.
- **`-c/--channel`**: implemented by calling `iw dev <iface> set channel <n>`.
- **WDS option (`-a`) fix**: the original C code accidentally wrote the WDS
  argument into the BSSID buffer. The Python port stores them separately.

## Getting sample packets

Pull frames out of a capture in Wireshark via `File → Export Packet Bytes`
and save as `.bin`. The original tool's sample packets are included in
`packets/`.

## Examples

> The samples below mirror those from the original README. They demonstrate
> disruptive behavior (deauth/disassoc floods) and must only be used against
> networks and devices you own or have explicit written authorization to test.

Replay a deauth frame against one client:

```sh
sudo python3 file2air.py -i wlan0mon -n 65000 \
    -d 00:01:02:03:04:05 -s 00:40:96:01:02:03 \
    -b 00:40:96:01:02:03 -f ./packets/deauth.bin
```

10 packets/sec with sequential sequence numbers starting at 0x100:

```sh
sudo python3 file2air.py -i wlan0mon -t -n 500 -Q 0x100 \
    -d ff:ff:ff:ff:ff:ff -f ./packets/proberesp.bin
```

## Credit

- Joshua Wright `<jwright@hasborg.com>` — original file2air (2005)
- FX `<fx@phenoelit.de>` / Phenoelit — original file2wire (2001)
- Larry Pesce — Python/scapy port

## License

GPL v2, matching the original. See `LICENSE`.
