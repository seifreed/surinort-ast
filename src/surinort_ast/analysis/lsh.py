"""
Locality-Sensitive Hashing (LSH) for Fast Similarity Search.

Implements LSH index for efficient approximate nearest neighbor search
on MinHash signatures.

Licensed under GNU General Public License v3.0
Author: Marc Rivero Lopez
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..core.nodes import Rule


class LSHIndex:
    """
    Locality-Sensitive Hashing index for fast similarity search.

    Uses banded LSH to hash MinHash signatures into buckets such that
    similar signatures are likely to hash to the same bucket.

    Args:
        threshold: Similarity threshold for candidate generation (0.0-1.0)
        num_bands: Number of bands to divide signature into
        rows_per_band: Number of rows (hash values) per band

    Example:
        >>> lsh = LSHIndex(threshold=0.8, num_bands=16)
        >>> lsh.add(rule1, signature1)
        >>> lsh.add(rule2, signature2)
        >>> candidates = lsh.query(signature1)
    """

    def __init__(
        self,
        threshold: float = 0.8,
        num_bands: int | None = None,
        rows_per_band: int | None = None,
    ) -> None:
        """
        Initialize LSH index.

        Args:
            threshold: Similarity threshold (0.0-1.0)
            num_bands: Number of bands (auto-calculated if None)
            rows_per_band: Rows per band (auto-calculated if None)

        Raises:
            ValueError: If threshold not in (0.0, 1.0] range
        """
        if not 0.0 < threshold <= 1.0:
            raise ValueError(f"threshold must be in (0.0, 1.0], got {threshold}")

        self.threshold = threshold

        # Auto-calculate optimal bands and rows if not provided
        if num_bands is None and rows_per_band is None:
            # Default: use 128 permutations with 16 bands
            self.num_bands = 16
            self.rows_per_band = 8
        elif num_bands is not None and rows_per_band is not None:
            self.num_bands = num_bands
            self.rows_per_band = rows_per_band
        elif num_bands is not None:
            # Calculate rows_per_band for 128 permutations
            self.num_bands = num_bands
            self.rows_per_band = 128 // num_bands
        else:
            # Calculate num_bands for 128 permutations
            assert rows_per_band is not None
            self.rows_per_band = rows_per_band
            self.num_bands = 128 // rows_per_band

        # Validate configuration
        total_perms = self.num_bands * self.rows_per_band
        if total_perms > 256:
            raise ValueError(f"Total permutations ({total_perms}) exceeds maximum (256)")

        # Storage: buckets[band_idx][bucket_hash] = list of (rule, signature)
        self.buckets: list[dict[int, list[tuple[Rule, list[int]]]]] = [
            defaultdict(list) for _ in range(self.num_bands)
        ]

        # Rule index for fast lookup
        self.rules: dict[int, tuple[Rule, list[int]]] = {}

    def _hash_band(self, band: list[int]) -> int:
        """
        Hash a band (list of hash values) to a bucket identifier.

        Args:
            band: List of hash values in the band

        Returns:
            Bucket hash (integer)
        """
        # Combine hash values using tuple hashing
        # This ensures different bands map to different spaces
        return hash(tuple(band))

    def _get_bands(self, signature: list[int]) -> list[list[int]]:
        """
        Split signature into bands.

        Args:
            signature: MinHash signature

        Returns:
            List of bands (each band is a list of hash values)

        Raises:
            ValueError: If signature length doesn't match expected size
        """
        expected_len = self.num_bands * self.rows_per_band
        if len(signature) < expected_len:
            # Pad signature if too short
            signature = signature + [0] * (expected_len - len(signature))
        elif len(signature) > expected_len:
            # Truncate signature if too long
            signature = signature[:expected_len]

        bands = []
        for i in range(self.num_bands):
            start = i * self.rows_per_band
            end = start + self.rows_per_band
            bands.append(signature[start:end])

        return bands

    def add(self, rule: Rule, signature: list[int]) -> None:
        """
        Add a rule with its signature to the LSH index.

        Args:
            rule: IDS rule to index
            signature: MinHash signature of the rule

        Example:
            >>> lsh = LSHIndex(threshold=0.8)
            >>> lsh.add(rule, signature)
        """
        # Get rule ID (use Python id as unique identifier)
        rule_id = id(rule)

        # Store rule and signature
        self.rules[rule_id] = (rule, signature)

        # Hash each band and add to corresponding bucket
        bands = self._get_bands(signature)
        for band_idx, band in enumerate(bands):
            bucket_hash = self._hash_band(band)
            self.buckets[band_idx][bucket_hash].append((rule, signature))

    def query(self, signature: list[int]) -> list[tuple[Rule, list[int]]]:
        """
        Query for candidate similar rules.

        Returns all rules that share at least one band with the query signature.

        Args:
            signature: MinHash signature to query

        Returns:
            List of (rule, signature) pairs that are candidates

        Example:
            >>> lsh = LSHIndex(threshold=0.8)
            >>> candidates = lsh.query(signature)
        """
        candidates: dict[int, tuple[Rule, list[int]]] = {}

        # Query each band
        bands = self._get_bands(signature)
        for band_idx, band in enumerate(bands):
            bucket_hash = self._hash_band(band)

            # Get all rules in the same bucket
            bucket = self.buckets[band_idx].get(bucket_hash, [])
            for rule, sig in bucket:
                rule_id = id(rule)
                if rule_id not in candidates:
                    candidates[rule_id] = (rule, sig)

        return list(candidates.values())

    def query_with_threshold(
        self, signature: list[int], min_similarity: float | None = None
    ) -> list[tuple[Rule, list[int], float]]:
        """
        Query for similar rules and filter by similarity threshold.

        Args:
            signature: MinHash signature to query
            min_similarity: Minimum similarity threshold (uses index threshold if None)

        Returns:
            List of (rule, signature, similarity) tuples above threshold

        Example:
            >>> lsh = LSHIndex(threshold=0.8)
            >>> results = lsh.query_with_threshold(signature, min_similarity=0.85)
        """
        from .minhash import MinHashSignature

        threshold = min_similarity if min_similarity is not None else self.threshold
        minhash = MinHashSignature(num_perm=len(signature))

        results = []
        candidates = self.query(signature)

        for rule, sig in candidates:
            similarity = minhash.estimate_similarity(signature, sig)
            if similarity >= threshold:
                results.append((rule, sig, similarity))

        # Sort by similarity descending
        results.sort(key=lambda x: x[2], reverse=True)

        return results

    def remove(self, rule: Rule) -> bool:
        """
        Remove a rule from the LSH index.

        Args:
            rule: Rule to remove

        Returns:
            True if rule was found and removed, False otherwise

        Example:
            >>> lsh = LSHIndex(threshold=0.8)
            >>> lsh.add(rule, signature)
            >>> lsh.remove(rule)
            True
        """
        rule_id = id(rule)

        if rule_id not in self.rules:
            return False

        # Get signature for removal
        _, signature = self.rules[rule_id]

        # Remove from rule index
        del self.rules[rule_id]

        # Remove from all buckets
        bands = self._get_bands(signature)
        for band_idx, band in enumerate(bands):
            bucket_hash = self._hash_band(band)
            bucket = self.buckets[band_idx].get(bucket_hash, [])

            # Filter out the rule
            self.buckets[band_idx][bucket_hash] = [(r, s) for r, s in bucket if id(r) != rule_id]

        return True

    def clear(self) -> None:
        """
        Clear all rules from the index.

        Example:
            >>> lsh = LSHIndex(threshold=0.8)
            >>> lsh.clear()
        """
        self.buckets = [defaultdict(list) for _ in range(self.num_bands)]
        self.rules.clear()

    def __len__(self) -> int:
        """
        Get number of rules in the index.

        Returns:
            Number of indexed rules
        """
        return len(self.rules)

    def stats(self) -> dict[str, Any]:
        """
        Get index statistics.

        Returns:
            Dictionary with index statistics

        Example:
            >>> lsh = LSHIndex(threshold=0.8)
            >>> stats = lsh.stats()
            >>> stats['num_rules']
            100
        """
        # Count non-empty buckets
        non_empty_buckets = 0
        total_bucket_size = 0
        max_bucket_size = 0

        for band in self.buckets:
            for bucket in band.values():
                if bucket:
                    non_empty_buckets += 1
                    size = len(bucket)
                    total_bucket_size += size
                    max_bucket_size = max(max_bucket_size, size)

        avg_bucket_size = total_bucket_size / non_empty_buckets if non_empty_buckets > 0 else 0

        return {
            "num_rules": len(self.rules),
            "num_bands": self.num_bands,
            "rows_per_band": self.rows_per_band,
            "threshold": self.threshold,
            "non_empty_buckets": non_empty_buckets,
            "avg_bucket_size": avg_bucket_size,
            "max_bucket_size": max_bucket_size,
        }
