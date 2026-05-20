#!/usr/bin/env python3
"""
file2air-python - inject 802.11 packets from binary files

A Python port of Joshua Wright's file2air (2005), replacing LORCON with
Scapy for packet injection on modern Linux mac80211 monitor-mode interfaces.

Intended for authorized wireless security testing, CTFs, lab work, and
research. The user is responsible for compliance with all applicable laws.

Original C tool: Copyright (c) 2005 Joshua Wright <jwright@hasborg.com>
Original file2wire: FX <fx@phenoelit.de>, Phenoelit (c) 2k1
Distributed under the GNU General Public License version 2.
"""

import argparse
import os
import re
import subprocess
import sys
import time

try:
    from scapy.all import RadioTap, sendp, conf
    from scapy.packet import Raw
except ImportError:
    sys.stderr.write(
        "error: scapy is required. Install with: pip install scapy\n"
    )
    sys.exit(1)


PROGNAME = "file2air-python"
VER = "1.1-py"
MAXPACKETSIZE = 2312
MINPACKETSIZE = 10
A4MINLEN = 30

conf.verb = 0


def hexdump(data: bytes) -> None:
    """Reproduce the lamont_hdump-style output from the original tool."""
    asciify = (
        "." * 32
        + "".join(chr(c) for c in range(32, 127))
        + "." * 129
    )
    length = len(data)
    print()
    for offset in range(0, length, 16):
        chunk = data[offset:offset + 16]
        hexparts = []
        for i in range(0, 16, 2):
            if i + 1 < len(chunk):
                hexparts.append("%04x" % ((chunk[i] << 8) | chunk[i + 1]))
            elif i < len(chunk):
                hexparts.append("%02x  " % chunk[i])
            else:
                hexparts.append("    ")
        ascii_part = "".join(asciify[c] for c in chunk)
        print("\t " + " ".join(hexparts) + "  " + ascii_part)


def parse_mac(s: str) -> bytes:
    """Validate and convert a MAC string to 6 raw bytes."""
    s = s.strip().lower()
    parts = re.split(r"[:\-]", s)
    if len(parts) != 6:
        raise ValueError(f"invalid MAC: {s!r}")
    out = bytearray(6)
    for i, p in enumerate(parts):
        if not p or len(p) > 2:
            raise ValueError(f"invalid MAC octet: {p!r}")
        v = int(p, 16)
        if v > 0xff:
            raise ValueError(f"invalid MAC octet value: {p!r}")
        out[i] = v
    return bytes(out)


def parse_seqnum(s: str) -> int:
    """Parse sequence number; accept 0x-prefixed hex like the C version."""
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s[2:], 16)
    return int(s, 10)


def parse_delay(s: str) -> int:
    """uX = X microseconds, X = X seconds. Returns microseconds."""
    if not s:
        return 0
    if s[0] == "u":
        return int(s[1:])
    return int(s) * 1_000_000


def set_channel(iface: str, channel: int, verbose: bool) -> None:
    """Switch the monitor-mode interface to the given channel via iw."""
    cmd = ["iw", "dev", iface, "set", "channel", str(channel)]
    if verbose:
        print("Running:", " ".join(cmd))
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except FileNotFoundError:
        sys.stderr.write("error: `iw` not found in PATH; cannot set channel.\n")
        raise SystemExit(1)
    except subprocess.CalledProcessError as e:
        msg = e.stderr.decode(errors="replace").strip()
        sys.stderr.write(f"error: failed to set channel: {msg}\n")
        raise SystemExit(1)


def header_len(frame: bytes) -> int:
    """Return the 802.11 MAC header length: 30 if both DS bits set, else 24."""
    if len(frame) < 2:
        return 24
    fc1 = frame[1]
    if (fc1 & 0x03) == 0x03:
        return A4MINLEN
    return 24


def override_addresses(frame: bytearray, dst, src, bssid, wds) -> None:
    if dst is not None:
        frame[4:10] = dst
    if src is not None:
        frame[10:16] = src
    if bssid is not None:
        frame[16:22] = bssid
    if wds is not None:
        frame[24:30] = wds


def set_seqnum(frame: bytearray, seqnum: int) -> None:
    """Write a 12-bit sequence number, preserving the fragment nibble.
    Sequence Control sits at frame[22:24] as a u16 little-endian:
    bits 0..3 = fragment number, bits 4..15 = sequence number."""
    cur = frame[22] | (frame[23] << 8)
    frag = cur & 0x000f
    val = ((seqnum & 0x0fff) << 4) | frag
    frame[22] = val & 0xff
    frame[23] = (val >> 8) & 0xff


def set_frag_and_more(frame: bytearray, frag_num: int, more_frag: bool) -> None:
    """Update fragment number and More Fragments flag for one fragment."""
    cur = frame[22] | (frame[23] << 8)
    seq = (cur >> 4) & 0x0fff
    val = (seq << 4) | (frag_num & 0x000f)
    frame[22] = val & 0xff
    frame[23] = (val >> 8) & 0xff
    if more_frag:
        frame[1] |= 0x04
    else:
        frame[1] &= ~0x04


def build_fragments(frame: bytes, pieces: int):
    """Mirror the C fragmentation logic: split the payload (bytes after the
    802.11 header) into `pieces` chunks, with More Fragments set on all but
    the final fragment, and an incrementing fragment number."""
    hdrlen = header_len(frame)
    payload_len = len(frame) - hdrlen
    if payload_len < pieces:
        raise ValueError(
            f"payload length ({payload_len}) must be >= number of fragments ({pieces})"
        )

    frag_size = payload_len // pieces
    if payload_len % pieces:
        last_frag_size = payload_len - frag_size * (pieces - 1)
    else:
        last_frag_size = 0

    wholefrags = pieces - 1 if last_frag_size > 0 else pieces

    header = frame[:hdrlen]
    payload = frame[hdrlen:]
    frags = []
    offset = 0

    for i in range(wholefrags):
        f = bytearray(header + payload[offset:offset + frag_size])
        is_last = (i == wholefrags - 1) and last_frag_size == 0
        set_frag_and_more(f, i, more_frag=not is_last)
        frags.append(bytes(f))
        offset += frag_size

    if last_frag_size > 0:
        f = bytearray(header + payload[offset:offset + last_frag_size])
        set_frag_and_more(f, wholefrags, more_frag=False)
        frags.append(bytes(f))

    return frags


def transmit(iface: str, frames, verbose: int) -> None:
    """Wrap each raw 802.11 frame in a RadioTap header and inject via scapy."""
    pkts = [RadioTap() / Raw(load=raw) for raw in frames]
    sendp(pkts, iface=iface, verbose=(verbose > 1))


def build_parser():
    p = argparse.ArgumentParser(
        prog=PROGNAME,
        add_help=False,
        description=f"{PROGNAME} v{VER} - inject 802.11 packets from binary files",
    )
    p.add_argument("-i", "--interface", help="Wireless monitor-mode interface")
    p.add_argument(
        "-r", "--driver", default=None,
        help="Driver name (LORCON-era compatibility shim; ignored by the scapy port)",
    )
    p.add_argument("-f", "--filename", help="Binary 802.11 frame to inject")
    p.add_argument("-c", "--channel", type=int, default=0, help="Channel number")
    p.add_argument("-n", "--count", type=int, default=1, help="Number of packets to send")
    p.add_argument(
        "-w", "--delay", default="",
        help="Delay between packets (uX for microseconds, X for seconds)",
    )
    p.add_argument(
        "-t", "--fast", action="store_true",
        help="Alias for -w u100000 (10 packets/sec)",
    )
    p.add_argument("-d", "--dest", help="Override destination address (addr1)")
    p.add_argument("-s", "--source", help="Override source address (addr2)")
    p.add_argument("-b", "--bssid", help="Override BSSID address (addr3)")
    p.add_argument("-a", "--wds", help="Override WDS address (addr4, 4-addr frames)")
    p.add_argument("-q", "--seqnum", help="Override sequence number (0x prefix for hex)")
    p.add_argument(
        "-Q", "--seqnuminc",
        help="Override sequence number and increment sequentially per packet",
    )
    p.add_argument(
        "-p", "--pieces", type=int, default=0,
        help="Fragment the payload into N pieces",
    )
    p.add_argument("-h", "--help", action="store_true", help="Show this help and exit")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Verbose output (repeat for more)")
    return p


def usage(parser, message=""):
    if message:
        sys.stderr.write(f"{PROGNAME}: {message}\n")
    parser.print_help()


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    print(
        f"{PROGNAME} v{VER} - inject 802.11 packets from binary files "
        "(scapy port of Joshua Wright's file2air)"
    )

    if args.help:
        usage(parser)
        return 0

    if not args.interface or not args.filename:
        usage(parser, "Must specify -i and -f")
        return 1

    delay_us = parse_delay("u100000" if args.fast else args.delay)

    seq_set = False
    seq_inc = False
    seq_val = 0
    if args.seqnum is not None:
        seq_set = True
        seq_val = parse_seqnum(args.seqnum)
    if args.seqnuminc is not None:
        seq_set = True
        seq_inc = True
        seq_val = parse_seqnum(args.seqnuminc)
    if seq_set and seq_val > 4095:
        sys.stderr.write("Invalid sequence number (max 4095).\n")
        return 1

    try:
        dst = parse_mac(args.dest) if args.dest else None
    except ValueError as e:
        usage(parser, f"Invalid dst address: {e}")
        return 1
    try:
        src = parse_mac(args.source) if args.source else None
    except ValueError as e:
        usage(parser, f"Invalid src address: {e}")
        return 1
    try:
        bssid = parse_mac(args.bssid) if args.bssid else None
    except ValueError as e:
        usage(parser, f"Invalid bssid address: {e}")
        return 1
    try:
        wds = parse_mac(args.wds) if args.wds else None
    except ValueError as e:
        usage(parser, f"Invalid WDS address: {e}")
        return 1

    try:
        st = os.stat(args.filename)
    except OSError as e:
        sys.stderr.write(f"stat: {e}\n")
        return 1

    if args.verbose:
        print(f"{args.filename} - {st.st_size} bytes raw data")

    if st.st_size > MAXPACKETSIZE:
        sys.stderr.write(
            f"Packet size too large ({st.st_size}). "
            f"Must be {MAXPACKETSIZE} or smaller.\n"
        )
        return 1
    if st.st_size < MINPACKETSIZE:
        sys.stderr.write(f"Error reading input file {args.filename}.\n")
        return 1

    with open(args.filename, "rb") as fp:
        frame = bytearray(fp.read())

    plen = len(frame)

    if args.channel != 0:
        set_channel(args.interface, args.channel, args.verbose > 0)

    override_addresses(frame, dst, src, bssid, None)

    if wds is not None:
        if plen < A4MINLEN:
            sys.stderr.write(f"Frame length ({plen}) too small for WDS.\n")
            return 1
        override_addresses(frame, None, None, None, wds)

    if seq_set:
        set_seqnum(frame, seq_val)

    if args.pieces > 1:
        hdrlen = header_len(bytes(frame))
        if (plen - hdrlen) < args.pieces:
            sys.stderr.write(
                f"Payload length ({plen - hdrlen}) too small to fragment "
                f"into {args.pieces} pieces.\n"
            )
            return 1

    print("Transmitting packets ... ", end="", flush=True)
    try:
        for _ in range(args.count):
            if args.verbose:
                hexdump(bytes(frame))
                print(f"Packet length: {len(frame)}")

            if args.pieces > 1:
                frames_to_send = build_fragments(bytes(frame), args.pieces)
            else:
                frames_to_send = [bytes(frame)]

            transmit(args.interface, frames_to_send, args.verbose)

            if delay_us:
                time.sleep(delay_us / 1_000_000)

            if seq_inc:
                cur = frame[22] | (frame[23] << 8)
                seq = (cur >> 4) & 0x0fff
                frag = cur & 0x000f
                seq = (seq + 1) & 0x0fff
                val = (seq << 4) | frag
                frame[22] = val & 0xff
                frame[23] = (val >> 8) & 0xff
    except PermissionError:
        sys.stderr.write(
            "\nerror: permission denied opening raw socket — run as root "
            "or grant CAP_NET_RAW.\n"
        )
        return 1
    except OSError as e:
        sys.stderr.write(f"\nerror: transmit failed: {e}\n")
        return 1

    print("Done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
