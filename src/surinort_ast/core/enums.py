"""
Enumerations for AST nodes.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from enum import Enum, auto
from typing import Any


class Action(str, Enum):
    """
    Rule actions for IDS/IPS systems.

    Each value is the lowercased member name; ``auto()`` derives it so no
    member is written as a bare string literal (which would trip bandit's
    B105 hardcoded-password heuristic on ``PASS``).

    Attributes:
        ALERT: Generate an alert (passive monitoring)
        LOG: Log the packet without alerting
        PASS: Ignore the packet (allow)
        DROP: Block the packet silently (Suricata/Snort3)
        REJECT: Block and send RST/ICMP unreachable (Suricata/Snort3)
        SDROP: Silent drop (Suricata specific)
    """

    @staticmethod
    def _generate_next_value_(name: str, *_: Any) -> str:
        return name.lower()

    ALERT = auto()
    LOG = auto()
    PASS = auto()
    DROP = auto()
    REJECT = auto()
    SDROP = auto()
    BLOCK = auto()
    REACT = auto()
    REWRITE = auto()


class Protocol(str, Enum):
    """
    Network protocols supported in rules.

    Includes both network-layer (TCP, UDP, ICMP, IP) and
    application-layer protocols (HTTP, DNS, TLS, etc.).
    """

    # Network layer
    TCP = "tcp"
    TCP_PKT = "tcp-pkt"
    TCP_STREAM = "tcp-stream"
    UDP = "udp"
    ICMP = "icmp"
    IP = "ip"
    IPV6 = "ipv6"
    FILE = "file"

    # Application layer (Suricata)
    HTTP = "http"
    HTTP1 = "http1"
    HTTP2 = "http2"
    BITTORRENT_DHT = "bittorrent-dht"
    DNS = "dns"
    TLS = "tls"
    SSH = "ssh"
    TELNET = "telnet"
    FTP = "ftp"
    FTP_DATA = "ftp-data"
    SMB = "smb"
    SMTP = "smtp"
    IMAP = "imap"
    DCERPC = "dcerpc"
    DHCP = "dhcp"
    NFS = "nfs"
    SIP = "sip"
    RDP = "rdp"
    MQTT = "mqtt"
    MODBUS = "modbus"
    DNP3 = "dnp3"
    ENIP = "enip"
    IKE = "ike"
    KRB5 = "krb5"
    NTP = "ntp"
    SNMP = "snmp"
    TFTP = "tftp"


class Direction(str, Enum):
    """
    Traffic direction in rule header.

    Attributes:
        TO: Unidirectional (->)
        FROM: Unidirectional reverse (<-)
        BIDIRECTIONAL: Bidirectional (<>)
    """

    TO = "->"
    FROM = "<-"
    BIDIRECTIONAL = "<>"


class Dialect(str, Enum):
    """
    IDS rule dialect/variant.

    Attributes:
        SURICATA: Suricata IDS/IPS rules
        SNORT2: Snort 2.x rules
        SNORT3: Snort 3.x rules
    """

    SURICATA = "suricata"
    SNORT2 = "snort2"
    SNORT3 = "snort3"


class DiagnosticLevel(str, Enum):
    """
    Diagnostic severity levels for parser errors and warnings.

    Attributes:
        ERROR: Parse error (rule invalid)
        WARNING: Potential issue (rule valid but suspicious)
        INFO: Informational message
    """

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ContentModifierType(str, Enum):
    """Content matching modifiers."""

    NOCASE = "nocase"
    OFFSET = "offset"
    DEPTH = "depth"
    DISTANCE = "distance"
    WITHIN = "within"
    RAWBYTES = "rawbytes"
    FAST_PATTERN = "fast_pattern"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    BSIZE = "bsize"


class FlowDirection(str, Enum):
    """Flow direction specifiers."""

    TO_CLIENT = "to_client"
    TO_SERVER = "to_server"
    FROM_CLIENT = "from_client"
    FROM_SERVER = "from_server"


class FlowState(str, Enum):
    """Flow state specifiers."""

    ESTABLISHED = "established"
    NOT_ESTABLISHED = "not_established"
    STATELESS = "stateless"
    ONLY_STREAM = "only_stream"
    NO_STREAM = "no_stream"
    ONLY_FRAG = "only_frag"
    NO_FRAG = "no_frag"


__all__ = [
    "Action",
    "ContentModifierType",
    "DiagnosticLevel",
    "Dialect",
    "Direction",
    "FlowDirection",
    "FlowState",
    "Protocol",
]
