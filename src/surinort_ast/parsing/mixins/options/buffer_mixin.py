"""
Buffer selection options transformer mixin.

Handles transformation of sticky buffer selection options for protocol-specific inspection:
- HTTP buffers: http.uri, http.header, http.method, http.cookie
- DNS buffers: dns_query, dns_answer
- TLS buffers: tls.sni, tls.cert_subject, tls.cert_issuer
- File buffers: file_data, file_name
- SSH buffers: ssh.proto, ssh.software

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from lark import Token
from lark.visitors import v_args

from ....core.nodes import BufferSelectOption


class BufferSelectionOptionsMixin:
    """
    Mixin for transforming buffer selection options.

    This mixin handles sticky buffer selection for protocol-specific inspection.
    Sticky buffers allow targeting specific protocol fields without complex
    byte patterns.

    Supported Protocols:
        - HTTP: http.uri, http.header, http.method, http.cookie, http.stat_code
        - DNS: dns_query, dns_answer
        - TLS/SSL: tls.sni, tls.cert_subject, tls.cert_issuer
        - File: file_data, file_name
        - SSH: ssh.proto, ssh.software
        - SMB: smb.named_pipe, smb.share

    Behavior:
        Once selected, subsequent content matches apply to this buffer until
        a different buffer is selected. This is why they're called "sticky" -
        the buffer selection sticks across multiple options.

    Example:
        http.uri; content:"malicious"; content:"payload";
        # Both content matches apply to http.uri buffer
    """

    @v_args(inline=True)
    def buffer_select_option(self, buffer_token: Token) -> BufferSelectOption:
        """
        Transform sticky buffer selection.

        Args:
            buffer_token: Token containing buffer name

        Returns:
            BufferSelectOption node with buffer name

        Usage:
            http.uri;
            dns_query;
            tls.sni;

        Sticky Buffers:
            Protocol-specific buffers for targeted inspection:
            - HTTP: http.uri, http.header, http.method, http.cookie
            - DNS: dns_query, dns_answer
            - TLS: tls.sni, tls.cert_subject, tls.cert_issuer
            - File: file_data, file_name
            - SSH: ssh.proto, ssh.software

        Behavior:
            Once selected, subsequent content matches apply to this buffer
            until a different buffer is selected. This is why they're called
            "sticky" - the buffer selection sticks across multiple options.
        """
        return BufferSelectOption(buffer_name=str(buffer_token.value))
