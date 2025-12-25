"""
Header transformation mixin for IDS rule parser.

This mixin handles transformation of rule header components including:
- Actions (alert, log, pass, drop, reject, sdrop)
- Protocols (tcp, udp, icmp, ip, http, tls, dns, etc.)
- Direction operators (->, <-, <>)
- Full header assembly

The mixin is designed to be composed with other transformer mixins in RuleTransformer.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from typing import Any

from lark.visitors import v_args

from ...core.enums import Action, Direction, Protocol
from ...core.nodes import Header


class HeaderTransformerMixin:
    """
    Mixin for transforming rule header AST nodes.

    This mixin provides methods for transforming Lark parse tree nodes into
    action, protocol, direction, and complete header AST nodes. It handles:
    - All IDS rule actions (alert, log, pass, drop, reject, sdrop)
    - All supported protocols (30+ including TCP, UDP, HTTP, TLS, DNS, etc.)
    - Direction operators (unidirectional and bidirectional)
    - Header assembly combining all components

    Protocol Support:
        This mixin supports protocols from multiple IDS generations:
        - Classic: tcp, udp, icmp, ip
        - Application: http, http2, tls/ssl, dns, smtp, ftp, ssh
        - Enterprise: smb, dcerpc, krb5, nfs
        - Industrial: modbus, dnp3, enip
        - Modern: mqtt, rdp, sip

    Dependencies:
        This mixin has no external dependencies on the parent class.
        All transformations are self-contained.
    """

    # ========================================================================
    # Actions
    # ========================================================================

    def alert(self, _: Any) -> Action:
        """
        Transform 'alert' action.

        Returns:
            Action.ALERT enum value
        """
        return Action.ALERT

    def log(self, _: Any) -> Action:
        """
        Transform 'log' action.

        Returns:
            Action.LOG enum value
        """
        return Action.LOG

    def pass_(self, _: Any) -> Action:
        """
        Transform 'pass' action.

        Returns:
            Action.PASS enum value

        Note:
            Named 'pass_' to avoid conflict with Python's 'pass' keyword.
        """
        return Action.PASS

    def drop(self, _: Any) -> Action:
        """
        Transform 'drop' action.

        Returns:
            Action.DROP enum value
        """
        return Action.DROP

    def reject(self, _: Any) -> Action:
        """
        Transform 'reject' action.

        Returns:
            Action.REJECT enum value
        """
        return Action.REJECT

    def sdrop(self, _: Any) -> Action:
        """
        Transform 'sdrop' action (silent drop).

        Returns:
            Action.SDROP enum value
        """
        return Action.SDROP

    # ========================================================================
    # Protocols
    # ========================================================================

    def tcp(self, _: Any) -> Protocol:
        """Transform 'tcp' protocol."""
        return Protocol.TCP

    def udp(self, _: Any) -> Protocol:
        """Transform 'udp' protocol."""
        return Protocol.UDP

    def icmp(self, _: Any) -> Protocol:
        """Transform 'icmp' protocol."""
        return Protocol.ICMP

    def ip(self, _: Any) -> Protocol:
        """Transform 'ip' protocol."""
        return Protocol.IP

    def http(self, _: Any) -> Protocol:
        """Transform 'http' protocol."""
        return Protocol.HTTP

    def http2(self, _: Any) -> Protocol:
        """Transform 'http2' protocol."""
        return Protocol.HTTP2

    def dns(self, _: Any) -> Protocol:
        """Transform 'dns' protocol."""
        return Protocol.DNS

    def tls(self, _: Any) -> Protocol:
        """Transform 'tls' protocol."""
        return Protocol.TLS

    def ssl(self, _: Any) -> Protocol:
        """
        Transform 'ssl' protocol (Snort3 alias for TLS).

        Returns:
            Protocol.TLS enum value

        Note:
            'ssl' is an alias for 'tls' in Snort3 for backward compatibility.
        """
        return Protocol.TLS

    def ssh(self, _: Any) -> Protocol:
        """Transform 'ssh' protocol."""
        return Protocol.SSH

    def ftp(self, _: Any) -> Protocol:
        """Transform 'ftp' protocol."""
        return Protocol.FTP

    def ftp_data(self, _: Any) -> Protocol:
        """Transform 'ftp-data' protocol."""
        return Protocol.FTP_DATA

    def smb(self, _: Any) -> Protocol:
        """Transform 'smb' protocol."""
        return Protocol.SMB

    def smtp(self, _: Any) -> Protocol:
        """Transform 'smtp' protocol."""
        return Protocol.SMTP

    def imap(self, _: Any) -> Protocol:
        """Transform 'imap' protocol."""
        return Protocol.IMAP

    def dcerpc(self, _: Any) -> Protocol:
        """Transform 'dcerpc' protocol."""
        return Protocol.DCERPC

    def dhcp(self, _: Any) -> Protocol:
        """Transform 'dhcp' protocol."""
        return Protocol.DHCP

    def nfs(self, _: Any) -> Protocol:
        """Transform 'nfs' protocol."""
        return Protocol.NFS

    def sip(self, _: Any) -> Protocol:
        """Transform 'sip' protocol."""
        return Protocol.SIP

    def rdp(self, _: Any) -> Protocol:
        """Transform 'rdp' protocol."""
        return Protocol.RDP

    def mqtt(self, _: Any) -> Protocol:
        """Transform 'mqtt' protocol."""
        return Protocol.MQTT

    def modbus(self, _: Any) -> Protocol:
        """Transform 'modbus' protocol (industrial control)."""
        return Protocol.MODBUS

    def dnp3(self, _: Any) -> Protocol:
        """Transform 'dnp3' protocol (industrial control)."""
        return Protocol.DNP3

    def enip(self, _: Any) -> Protocol:
        """Transform 'enip' protocol (Ethernet/IP industrial)."""
        return Protocol.ENIP

    def ike(self, _: Any) -> Protocol:
        """Transform 'ike' protocol (IPsec key exchange)."""
        return Protocol.IKE

    def krb5(self, _: Any) -> Protocol:
        """Transform 'krb5' protocol (Kerberos)."""
        return Protocol.KRB5

    def ntp(self, _: Any) -> Protocol:
        """Transform 'ntp' protocol."""
        return Protocol.NTP

    def snmp(self, _: Any) -> Protocol:
        """Transform 'snmp' protocol."""
        return Protocol.SNMP

    def tftp(self, _: Any) -> Protocol:
        """Transform 'tftp' protocol."""
        return Protocol.TFTP

    # ========================================================================
    # Direction
    # ========================================================================

    def to(self, _: Any) -> Direction:
        """
        Transform '->' direction (unidirectional to destination).

        Returns:
            Direction.TO enum value
        """
        return Direction.TO

    def from_dir(self, _: Any) -> Direction:
        """
        Transform '<-' direction (unidirectional from destination).

        Returns:
            Direction.FROM enum value

        Note:
            Named 'from_dir' to avoid conflict with Python's 'from' keyword.
        """
        return Direction.FROM

    def bidirectional(self, _: Any) -> Direction:
        """
        Transform '<>' direction (bidirectional traffic).

        Returns:
            Direction.BIDIRECTIONAL enum value
        """
        return Direction.BIDIRECTIONAL

    # ========================================================================
    # Header
    # ========================================================================

    @v_args(inline=True)
    def header(
        self,
        protocol: Protocol,
        src_addr: Any,
        src_port: Any,
        direction: Direction,
        dst_addr: Any,
        dst_port: Any,
    ) -> Header:
        """
        Transform complete rule header.

        Args:
            protocol: Protocol enum value
            src_addr: Source address expression (AddressExpr)
            src_port: Source port expression (PortExpr)
            direction: Direction enum value
            dst_addr: Destination address expression (AddressExpr)
            dst_port: Destination port expression (PortExpr)

        Returns:
            Header node containing all header components

        Header Structure:
            A rule header defines the network traffic pattern to match:
            - protocol: What protocol to inspect (tcp, udp, http, etc.)
            - src_addr/src_port: Source network location
            - direction: Traffic flow direction (to, from, bidirectional)
            - dst_addr/dst_port: Destination network location

        Example:
            tcp $HOME_NET any -> $EXTERNAL_NET 80
        """
        return Header(
            protocol=protocol,
            src_addr=src_addr,
            src_port=src_port,
            direction=direction,
            dst_addr=dst_addr,
            dst_port=dst_port,
        )
