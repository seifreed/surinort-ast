"""
File operations and tagging options transformer mixin.

Handles transformation of file and packet tagging options including:
- filestore: Extract files from traffic for analysis
- tag: Mark related packets for capture
- flags: TCP flag combinations matching

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from lark import Token

from ....core.nodes import FilestoreOption, GenericOption


class FileOperationsOptionsMixin:
    """
    Mixin for transforming file operations and tagging options.

    This mixin handles:
    - filestore: Automatic file extraction from traffic
    - tag: Mark related packets for forensic capture
    - flags: TCP flag pattern matching

    Use Cases:
        - Extract malicious files from traffic for analysis
        - Capture related packets after alert for forensics
        - Detect TCP handshake anomalies and port scans
    """

    # ========================================================================
    # File Extraction Options
    # ========================================================================

    def filestore_option(self, items: Sequence[Any]) -> FilestoreOption:
        """
        Transform filestore option (extract files from traffic).

        Args:
            items: List containing optional direction and scope parameters

        Returns:
            FilestoreOption node with direction and scope

        Usage:
            filestore;
            filestore:request,file;
            filestore:response,both;

        Direction:
            - request: Extract from client request
            - response: Extract from server response
            - both: Extract from both directions

        Scope:
            - file: Store only the file
            - both: Store file and packet capture

        Use Case:
            Automatically extract malicious files (malware, exploits) for analysis.
        """
        direction = None
        scope = None

        if items and len(items) > 0:
            params = items[0] if isinstance(items[0], (list, tuple)) else items
            if len(params) >= 1:
                direction = str(params[0].value if isinstance(params[0], Token) else params[0])
            if len(params) >= 2:
                scope = str(params[1].value if isinstance(params[1], Token) else params[1])

        return FilestoreOption(direction=direction, scope=scope)

    def filestore_params(self, items: Sequence[Token]) -> Sequence[Token]:
        """Pass through filestore params."""
        return items

    # ========================================================================
    # Packet Tagging Options
    # ========================================================================

    def tag_option(self, items: Sequence[Any]) -> GenericOption:
        """
        Transform tag option (mark related packets).

        Args:
            items: List containing tag parameters

        Returns:
            GenericOption with keyword="tag" and value string

        Usage:
            tag:session,10,packets;
            tag:host,60,seconds,src;

        Tag Types:
            - session: Tag entire flow
            - host: Tag packets to/from host

        Parameters:
            - count: Number of packets or time duration
            - metric: packets, seconds, or bytes
            - direction: src or dst (for host tagging)

        Use Case:
            Capture related packets after alert triggers for forensic analysis.
        """
        value_str = ""
        if items:
            tok = items[0]
            value_str = str(tok.value) if isinstance(tok, Token) else str(tok)
            value_str = value_str.strip()
        return GenericOption(keyword="tag", value=value_str, raw=f"tag:{value_str}")

    def tag_params(self, items: Sequence[Token]) -> Sequence[Token]:
        """Legacy handler (not used with new TAG_VALUE) - keep for compatibility."""
        return items

    # ========================================================================
    # TCP Flags Options
    # ========================================================================

    def flags_option(self, items: Sequence[Token]) -> GenericOption:
        """
        Transform flags option (TCP flag combinations).

        Args:
            items: List containing flags value

        Returns:
            GenericOption with keyword="flags" and flags string

        Usage:
            flags:S;          (SYN)
            flags:SA;         (SYN+ACK)
            flags:F,12;       (FIN, with mask 12)
            flags:!A;         (Not ACK)
            flags:*S;         (SYN present, others optional)
            flags:+S;         (SYN and others present)

        TCP Flags:
            - S: SYN (synchronize)
            - A: ACK (acknowledge)
            - F: FIN (finish)
            - R: RST (reset)
            - P: PSH (push)
            - U: URG (urgent)
            - C: CWR (congestion window reduced)
            - E: ECE (ECN echo)

        Modifiers:
            - !: Negation (flag not set)
            - *: Flag must be set, others optional
            - +: Flag and at least one other must be set

        Use Case:
            Detect specific TCP handshake patterns, port scans, or anomalies.
        """
        value = ""
        if items:
            tok = items[0]
            value = str(tok.value) if isinstance(tok, Token) else str(tok)
            value = value.strip()
        return GenericOption(keyword="flags", value=value, raw=f"flags:{value}")
