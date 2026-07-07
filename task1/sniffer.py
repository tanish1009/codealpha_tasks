

import time

from PyQt5.QtCore import QThread, pyqtSignal

from scapy.all import sniff
from scapy.packet import Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS

# Individual TCP flag bits, checked in this fixed order so the resulting
# string is always SYN/ACK/FIN/RST/PSH ordering (only the flags that are
# actually set get included).
_TCP_FLAG_BITS = (
    ("SYN", 0x02),
    ("ACK", 0x10),
    ("FIN", 0x01),
    ("RST", 0x04),
    ("PSH", 0x08),
)

MAX_PAYLOAD_CHARS = 80
NO_VALUE = "\u2014"  # em dash, used for ports on non-TCP/UDP protocols


def _tcp_flags_str(flags):
    """Turn a scapy TCP flags value into a slash-joined string, e.g. 'SYN/ACK'."""
    try:
        bits = int(flags)
    except (TypeError, ValueError):
        return ""
    names = [name for name, mask in _TCP_FLAG_BITS if bits & mask]
    return "/".join(names)


def _extract_payload(pkt):
    """Return printable-ASCII rendering of the packet's raw payload.

    Non-printable bytes become '.'. The result is capped at
    MAX_PAYLOAD_CHARS characters, with a '...' suffix appended if the
    payload was truncated.
    """
    if not pkt.haslayer(Raw):
        return ""

    try:
        data = bytes(pkt[Raw].load)
    except Exception:
        return ""

    chars = []
    for b in data:
        if 32 <= b < 127:
            chars.append(chr(b))
        else:
            chars.append(".")
    text = "".join(chars)

    if len(text) > MAX_PAYLOAD_CHARS:
        return text[:MAX_PAYLOAD_CHARS] + "..."
    return text


def parse_packet(pkt):
    """Convert a scapy packet into a dict describing it.

    Returned keys: time, proto, src_ip, src_port, dst_ip, dst_port,
    size, flags, payload.
    """
    # Timestamp
    try:
        ts = float(pkt.time)
    except (AttributeError, TypeError, ValueError):
        ts = time.time()
    time_str = time.strftime("%H:%M:%S", time.localtime(ts))

    # IP addresses (best-effort; non-IP traffic won't have these)
    src_ip = NO_VALUE
    dst_ip = NO_VALUE
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

    src_port = NO_VALUE
    dst_port = NO_VALUE
    flags = ""
    proto = "OTHER"

    # Priority order: DNS -> TCP -> UDP -> ICMP -> OTHER
    if pkt.haslayer(DNS):
        proto = "DNS"
        if pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = _tcp_flags_str(pkt[TCP].flags)
    elif pkt.haslayer(TCP):
        proto = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags = _tcp_flags_str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        proto = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
    else:
        proto = "OTHER"

    try:
        size = len(pkt)
    except Exception:
        size = 0

    payload = _extract_payload(pkt)

    return {
        "time": time_str,
        "proto": proto,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "size": size,
        "flags": flags,
        "payload": payload,
    }


class SnifferThread(QThread):
    """Runs scapy.sniff() in a background thread and emits parsed packets."""

    packet_received = pyqtSignal(dict)
    status_changed = pyqtSignal(str)

    def __init__(self, iface=None, bpf_filter="", parent=None):
        super().__init__(parent)
        self.iface = iface
        self.bpf_filter = (bpf_filter or "").strip()
        self._stop_flag = False

    def run(self):
        self._stop_flag = False
        try:
            sniff_kwargs = {
                "prn": self._on_packet,
                "store": False,
                "stop_filter": self._should_stop,
            }
            if self.iface:
                sniff_kwargs["iface"] = self.iface
            # Only pass the filter kwarg if it's non-empty -- an empty
            # string is not a valid BPF filter for scapy/libpcap.
            if self.bpf_filter:
                sniff_kwargs["filter"] = self.bpf_filter

            self.status_changed.emit("Capturing on {}".format(self.iface or "default interface"))
            sniff(**sniff_kwargs)
            self.status_changed.emit("Stopped")
        except Exception as exc:
            self.status_changed.emit("error: {}".format(exc))

    def _on_packet(self, pkt):
        if self._stop_flag:
            return
        try:
            data = parse_packet(pkt)
            self.packet_received.emit(data)
        except Exception:
            # A single malformed packet should never kill the capture thread.
            pass

    def _should_stop(self, pkt):
        return self._stop_flag

    def stop(self):
        self._stop_flag = True
