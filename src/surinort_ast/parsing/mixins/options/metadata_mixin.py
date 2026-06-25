"""
Metadata options transformer mixin.

Handles transformation of rule metadata options including:
- Basic identifiers: msg, sid, rev, gid
- Classification: classtype, priority
- References: reference (CVE, bugtraq, URL, etc.)
- Custom metadata: metadata (key-value pairs)

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from lark import Token
from lark.visitors import v_args

from ...helpers import token_to_str

if TYPE_CHECKING:
    from .. import DiagnosticReporter

from ....core.nodes import (
    ClasstypeOption,
    GidOption,
    MetadataOption,
    MsgOption,
    PriorityOption,
    ReferenceOption,
    RevOption,
    SidOption,
)
from .._location_aware import LocationAwareMixin
from ._helpers import parse_quoted_string_cached


class MetadataOptionsMixin(LocationAwareMixin):
    """
    Mixin for transforming rule metadata options.

    This mixin handles basic rule identification and classification:
    - msg: Human-readable rule description
    - sid: Signature ID (unique identifier)
    - rev: Rule revision number
    - gid: Generator ID (rule source identifier)
    - classtype: Rule classification category
    - priority: Alert priority level (>= 1; lower means higher priority)
    - reference: External references (CVE, URLs, etc.)
    - metadata: Key-value metadata pairs

    Dependencies:
        This mixin expects the following attributes/methods on the parent class:
        - file_path: str | None - Source file path for location tracking
        - add_diagnostic(level, message, location) - Diagnostic reporting method
    """

    # Declare expected attributes for type checking
    add_diagnostic: DiagnosticReporter

    # ========================================================================
    # Basic Identification Options
    # ========================================================================

    @v_args(inline=True)
    def msg_option(self, text_token: Token) -> MsgOption:
        """
        Transform msg option (rule description).

        Args:
            text_token: Token containing quoted message text

        Returns:
            MsgOption node with parsed message text

        Usage:
            msg:"Malicious traffic detected";

        Note:
            The msg option provides a human-readable description of what
            the rule detects. It appears in alerts and logs.
        """
        text = parse_quoted_string_cached(str(text_token.value))
        return MsgOption(text=text, location=self._location_for(text_token))

    @v_args(inline=True)
    def sid_option(self, sid_token: Token) -> SidOption:
        """
        Transform sid option (signature ID).

        Args:
            sid_token: Token containing signature ID integer

        Returns:
            SidOption node with signature ID

        Usage:
            sid:1000001;

        SID Ranges:
            - 0-99: Reserved
            - 100-999999: Snort/Suricata official rules
            - 1000000+: Custom rules

        Note:
            Pydantic Field validators ensure SID >= 1 per IDS specifications.
        """
        sid = int(sid_token.value)
        return SidOption(value=sid, location=self._location_for(sid_token))

    @v_args(inline=True)
    def rev_option(self, rev_token: Token) -> RevOption:
        """
        Transform rev option (rule revision).

        Args:
            rev_token: Token containing revision integer

        Returns:
            RevOption node with revision number

        Usage:
            rev:1;

        Revision Management:
            Increment rev when rule logic changes but sid remains the same.
            This allows IDS engines to track rule updates.

        Note:
            Pydantic Field validators ensure rev >= 1 per IDS specifications.
        """
        rev = int(rev_token.value)
        return RevOption(value=rev, location=self._location_for(rev_token))

    @v_args(inline=True)
    def gid_option(self, gid_token: Token) -> GidOption:
        """
        Transform gid option (generator ID).

        Args:
            gid_token: Token containing generator ID integer

        Returns:
            GidOption node with generator ID

        Usage:
            gid:1;

        Generator IDs:
            - 1: Standard rules
            - 2-99: Reserved for specific preprocessors
            - 100+: Custom generators
        """
        gid = int(gid_token.value)
        return GidOption(value=gid, location=self._location_for(gid_token))

    # ========================================================================
    # Classification Options
    # ========================================================================

    @v_args(inline=True)
    def classtype_option(self, classtype_token: Token) -> ClasstypeOption:
        """
        Transform classtype option (rule classification).

        Args:
            classtype_token: Token containing classtype identifier

        Returns:
            ClasstypeOption node with classtype name

        Usage:
            classtype:trojan-activity;

        Common Classtypes:
            - trojan-activity: Trojan or backdoor behavior
            - web-application-attack: Web application exploit
            - attempted-admin: Attempt to gain admin privileges
            - successful-admin: Successful admin access
            - denial-of-service: DoS or DDoS attack
        """
        classtype = str(classtype_token.value)
        return ClasstypeOption(value=classtype, location=self._location_for(classtype_token))

    @v_args(inline=True)
    def priority_option(self, priority_token: Token) -> PriorityOption:
        """
        Transform priority option (alert priority).

        Args:
            priority_token: Token containing priority integer

        Returns:
            PriorityOption node with priority level

        Usage:
            priority:1;

        Priority Levels:
            Lower numbers mean higher priority. Snort documents 1-255;
            Suricata imposes no upper bound.

        Note:
            The Pydantic Field validator enforces only the lower bound (>= 1).
        """
        priority = int(priority_token.value)
        return PriorityOption(value=priority, location=self._location_for(priority_token))

    # ========================================================================
    # Reference Options
    # ========================================================================

    @v_args(inline=True)
    def reference_option(self, ref_type_token: Token, ref_id: Any) -> ReferenceOption:
        """
        Transform reference option (external reference).

        Args:
            ref_type_token: Token containing reference type (cve, url, bugtraq, etc.)
            ref_id: Reference identifier (Token or string)

        Returns:
            ReferenceOption node with reference type and ID

        Usage:
            reference:cve,2021-12345;
            reference:url,example.com/advisory;

        Common Reference Types:
            - cve: CVE identifier
            - url: Web URL
            - bugtraq: BugTraq ID
            - nessus: Nessus plugin ID
            - mcafee: McAfee threat ID
        """
        ref_type = str(ref_type_token.value)
        # ref_id can be Token or already processed string
        ref_id_str = token_to_str(ref_id)
        return ReferenceOption(
            ref_type=ref_type,
            ref_id=ref_id_str,
            location=self._location_for(ref_type_token),
        )

    def reference_id(self, items: Sequence[Token]) -> str:
        """
        Extract reference ID from tokens.

        Args:
            items: Sequence of tokens forming the reference ID

        Returns:
            Reference ID string

        Note:
            Reference IDs can be WORD, INT, or complex patterns like URLs.
        """
        if items:
            return str(items[0].value)
        return ""

    # ========================================================================
    # Metadata Options
    # ========================================================================

    def metadata_option(self, items: Sequence[Any]) -> MetadataOption:
        """
        Transform metadata option (key-value metadata).

        Args:
            items: Sequence of (key, value) tuples from metadata_entry

        Returns:
            MetadataOption node with list of key-value pairs

        Usage:
            metadata:key1 value1, key2 value2;

        Metadata Use Cases:
            - Rule management (author, created_at, updated_at)
            - Threat intelligence (attack_target, affected_product)
            - Compliance (cis_id, nist_id)
            - Custom categorization
        """
        entries: list[tuple[str, str]] = []

        for item in items:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                entries.append((str(item[0]), str(item[1])))

        return MetadataOption(entries=entries)

    def metadata_entry(self, items: Sequence[Any]) -> tuple[str, str]:
        """
        Transform metadata entry (key followed by values).

        Args:
            items: Sequence of tokens representing key and values

        Returns:
            Tuple of (key, value) where value is space-joined

        Grammar:
            metadata_entry: key value1 value2...

        Note:
            First value is the key, remaining values are concatenated.
            This allows multi-word values like "created_at 2021 01 15".
        """
        if not items:
            return ("", "")

        # Extract values from tokens or trees
        from lark import Tree

        values = []
        for item in items:
            if isinstance(item, Token):
                values.append(str(item.value))
            elif isinstance(item, Tree):
                # Tree from metadata_word - extract first child token
                if item.children:
                    child = item.children[0]
                    if isinstance(child, Token):
                        values.append(str(child.value))
            elif isinstance(item, str):
                values.append(item)

        if not values:
            return ("", "")

        # First value is the key, rest are concatenated as the value
        key = values[0]
        value = " ".join(values[1:]) if len(values) > 1 else ""
        return (key, value)
