"""
MinHash Algorithm for Rule Similarity Detection.

Implements MinHash fingerprinting to generate compact signatures from IDS rules
for efficient similarity computation.

Licensed under GNU General Public License v3.0
Author: Marc Rivero Lopez
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any

from ..core.nodes import (
    AnyAddress,
    AnyPort,
    ContentOption,
    Option,
    PcreOption,
    Rule,
)


class MinHashSignature:
    """
    MinHash signature generator for IDS rules.

    Uses MinHash algorithm to create compact fingerprints that preserve
    Jaccard similarity between rule feature sets.

    Args:
        num_perm: Number of hash permutations (default: 128)
        seed: Random seed for reproducibility (default: 42)

    Example:
        >>> minhash = MinHashSignature(num_perm=128)
        >>> signature = minhash.create_signature(rule)
        >>> len(signature)
        128
    """

    def __init__(self, num_perm: int = 128, seed: int = 42) -> None:
        """
        Initialize MinHash signature generator.

        Args:
            num_perm: Number of hash permutations (must be positive)
            seed: Random seed for hash function generation

        Raises:
            ValueError: If num_perm <= 0
        """
        if num_perm <= 0:
            raise ValueError(f"num_perm must be positive, got {num_perm}")

        self.num_perm = num_perm
        self.seed = seed
        self._hash_functions = self._generate_hash_functions()

    def _generate_hash_functions(self) -> list[tuple[int, int]]:
        """
        Generate hash function parameters using linear hashing.

        Each hash function is defined as: h(x) = (a * x + b) mod prime
        where a and b are random coefficients.

        Returns:
            List of (a, b) coefficient pairs for hash functions
        """
        # Use a large prime for modulo operation
        # We'll use 2^31 - 1 (Mersenne prime) for efficient computation
        prime = (1 << 31) - 1

        # Generate deterministic random coefficients from seed
        hash_functions = []
        rng_state = self.seed

        for _ in range(self.num_perm):
            # Generate deterministic pseudo-random numbers
            rng_state = (rng_state * 1103515245 + 12345) & 0x7FFFFFFF
            a = rng_state % prime
            if a == 0:
                a = 1  # Ensure a is non-zero

            rng_state = (rng_state * 1103515245 + 12345) & 0x7FFFFFFF
            b = rng_state % prime

            hash_functions.append((a, b))

        return hash_functions

    def _hash_value(self, value: str) -> int:
        """
        Hash a string value to an integer using SHA-256.

        Args:
            value: String to hash

        Returns:
            32-bit unsigned integer hash
        """
        # Use SHA-256 for cryptographic quality hashing
        hash_bytes = hashlib.sha256(value.encode("utf-8")).digest()
        # Take first 4 bytes and convert to unsigned int
        # struct.unpack returns tuple, extract first element
        result: int = struct.unpack("<I", hash_bytes[:4])[0]
        return result

    def _extract_features(self, rule: Rule) -> set[str]:
        """
        Extract features from a rule for similarity comparison.

        Features include:
        - Protocol fingerprint
        - Port patterns (non-wildcard)
        - Content patterns (normalized)
        - PCRE patterns (normalized)
        - Option types
        - Metadata values

        Args:
            rule: IDS rule to extract features from

        Returns:
            Set of feature strings
        """
        features: set[str] = set()

        # Header features
        features.add(f"protocol:{rule.header.protocol.value}")
        features.add(f"direction:{rule.header.direction.value}")

        # Add port information (skip if 'any')
        if not isinstance(rule.header.src_port, AnyPort):
            features.add(f"src_port:{self._port_to_string(rule.header.src_port)}")
        if not isinstance(rule.header.dst_port, AnyPort):
            features.add(f"dst_port:{self._port_to_string(rule.header.dst_port)}")

        # Add address patterns (skip if 'any')
        if not isinstance(rule.header.src_addr, AnyAddress):
            features.add(f"src_addr:{self._addr_to_string(rule.header.src_addr)}")
        if not isinstance(rule.header.dst_addr, AnyAddress):
            features.add(f"dst_addr:{self._addr_to_string(rule.header.dst_addr)}")

        # Extract option features
        for option in rule.options:
            features.update(self._extract_option_features(option))

        return features

    def _port_to_string(self, port: Any) -> str:
        """
        Convert port expression to normalized string.

        Args:
            port: Port expression (Port, PortRange, PortList, etc.)

        Returns:
            Normalized string representation
        """
        # Handle different port types
        if hasattr(port, "value"):
            return str(port.value)
        if hasattr(port, "start") and hasattr(port, "end"):
            return f"{port.start}-{port.end}"
        if hasattr(port, "elements"):
            return ",".join(self._port_to_string(p) for p in port.elements)
        return str(port)

    def _addr_to_string(self, addr: Any) -> str:
        """
        Convert address expression to normalized string.

        Args:
            addr: Address expression (IPAddress, IPCIDRRange, etc.)

        Returns:
            Normalized string representation
        """
        # Handle different address types
        if hasattr(addr, "value"):
            value: str = str(addr.value)
            return value
        if hasattr(addr, "network") and hasattr(addr, "prefix_len"):
            return f"{addr.network}/{addr.prefix_len}"
        if hasattr(addr, "elements"):
            return ",".join(self._addr_to_string(a) for a in addr.elements)
        if hasattr(addr, "name"):
            return f"${addr.name}"
        return str(addr)

    def _extract_option_features(self, option: Option) -> set[str]:
        """
        Extract features from a single option.

        Args:
            option: Rule option to extract features from

        Returns:
            Set of feature strings
        """
        features: set[str] = set()

        # Skip metadata options that don't contribute to similarity
        metadata_options = {
            "MsgOption",
            "SidOption",
            "RevOption",
            "GidOption",
            "ClasstypeOption",
            "PriorityOption",
            "ReferenceOption",
            "MetadataOption",
        }

        option_type = option.__class__.__name__

        # Skip metadata options entirely
        if option_type in metadata_options:
            return features

        # Add option type
        features.add(f"option:{option_type}")

        # Content option: extract normalized content
        if isinstance(option, ContentOption):
            if hasattr(option, "pattern") and option.pattern:
                # Normalize content: lowercase for case-insensitive comparison
                normalized = self._normalize_content(option.pattern)
                features.add(f"content:{normalized}")

                # Add content modifiers
                if hasattr(option, "modifiers") and option.modifiers:
                    for mod in option.modifiers:
                        if hasattr(mod, "name"):
                            features.add(f"content_mod:{mod.name.value}")

        # PCRE option: extract normalized pattern
        elif isinstance(option, PcreOption):
            if hasattr(option, "pattern") and option.pattern:
                normalized = self._normalize_pcre(option.pattern)
                features.add(f"pcre:{normalized}")

        # Other options: extract key-value pairs
        else:
            # Extract option data
            if hasattr(option, "keyword"):
                features.add(f"keyword:{option.keyword}")
            if hasattr(option, "value") and option.value is not None:
                features.add(f"value:{str(option.value)[:100]}")  # Limit length

        return features

    def _normalize_content(self, content: str | bytes) -> str:
        """
        Normalize content pattern for comparison.

        Args:
            content: Content pattern (string or bytes)

        Returns:
            Normalized lowercase string
        """
        if isinstance(content, bytes):
            # Try to decode as ASCII/UTF-8 for case-insensitive comparison
            try:
                decoded = content.decode("utf-8", errors="strict")
                # Successfully decoded - normalize to lowercase
                return decoded.lower()
            except (UnicodeDecodeError, AttributeError):
                # Binary content - convert to hex (already lowercase)
                return content.hex().lower()
        # Normalize to lowercase for case-insensitive matching
        return content.lower()

    def _normalize_pcre(self, pattern: str) -> str:
        """
        Normalize PCRE pattern for comparison.

        Args:
            pattern: PCRE regex pattern

        Returns:
            Normalized pattern
        """
        # Remove common PCRE delimiters and flags
        normalized = pattern.strip()
        if normalized.startswith("/") and normalized.rfind("/") > 0:
            # Extract pattern between slashes
            last_slash = normalized.rfind("/")
            normalized = normalized[1:last_slash]
        return normalized.lower()

    def create_signature(self, rule: Rule) -> list[int]:
        """
        Create MinHash signature for a rule.

        The signature is a list of hash values representing the minimum
        hash value for each permutation across all features.

        Args:
            rule: IDS rule to fingerprint

        Returns:
            List of num_perm hash values (signature)

        Example:
            >>> minhash = MinHashSignature(num_perm=128)
            >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
            >>> sig = minhash.create_signature(rule)
            >>> len(sig)
            128
        """
        # Extract features
        features = self._extract_features(rule)

        if not features:
            # Empty rule: return all zeros
            return [0] * self.num_perm

        # Initialize signature with maximum values
        prime = (1 << 31) - 1
        signature = [prime] * self.num_perm

        # For each feature, compute hash for each permutation
        for feature in features:
            feature_hash = self._hash_value(feature)

            for i, (a, b) in enumerate(self._hash_functions):
                # Compute permuted hash: h(x) = (a * x + b) mod prime
                h = (a * feature_hash + b) % prime
                # Keep minimum hash for this permutation
                signature[i] = min(signature[i], h)

        return signature

    def estimate_similarity(self, sig1: list[int], sig2: list[int]) -> float:
        """
        Estimate Jaccard similarity from two MinHash signatures.

        The similarity is estimated as the fraction of matching hash values
        in the signatures.

        Args:
            sig1: First MinHash signature
            sig2: Second MinHash signature

        Returns:
            Estimated Jaccard similarity (0.0 to 1.0)

        Raises:
            ValueError: If signatures have different lengths

        Example:
            >>> minhash = MinHashSignature()
            >>> sim = minhash.estimate_similarity(sig1, sig2)
            >>> 0.0 <= sim <= 1.0
            True
        """
        if len(sig1) != len(sig2):
            raise ValueError(f"Signature length mismatch: {len(sig1)} vs {len(sig2)}")

        if not sig1:
            return 0.0

        # Count matching hash values
        matches = sum(1 for h1, h2 in zip(sig1, sig2, strict=False) if h1 == h2)

        # Estimate Jaccard similarity
        return matches / len(sig1)
