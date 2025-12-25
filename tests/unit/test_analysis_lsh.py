# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for surinort_ast.analysis.lsh module.

Tests the LSHIndex class for locality-sensitive hashing and fast
similarity search on MinHash signatures.

All tests use real signatures and validate actual LSH operations.
"""

import pytest

from surinort_ast import parse_rule
from surinort_ast.analysis.lsh import LSHIndex
from surinort_ast.analysis.minhash import MinHashSignature


class TestLSHIndexInitialization:
    """Test LSH index initialization and configuration."""

    def test_lsh_initialization_default(self):
        """Test creating LSH index with default parameters."""
        lsh = LSHIndex()

        assert lsh.threshold == 0.8
        assert lsh.num_bands == 16
        assert lsh.rows_per_band == 8
        assert len(lsh.buckets) == 16

    def test_lsh_initialization_custom_threshold(self):
        """Test creating LSH index with custom threshold."""
        lsh = LSHIndex(threshold=0.7)

        assert lsh.threshold == 0.7
        assert lsh.num_bands > 0
        assert lsh.rows_per_band > 0

    def test_lsh_initialization_custom_bands(self):
        """Test creating LSH index with custom bands."""
        lsh = LSHIndex(threshold=0.8, num_bands=20, rows_per_band=10)

        assert lsh.num_bands == 20
        assert lsh.rows_per_band == 10

    def test_lsh_invalid_threshold(self):
        """Test that invalid thresholds raise ValueError."""
        with pytest.raises(ValueError):
            LSHIndex(threshold=0.0)

        with pytest.raises(ValueError):
            LSHIndex(threshold=1.5)

        with pytest.raises(ValueError):
            LSHIndex(threshold=-0.1)

    def test_lsh_valid_threshold_boundaries(self):
        """Test valid threshold boundaries."""
        lsh_low = LSHIndex(threshold=0.01)
        assert lsh_low.threshold == 0.01

        lsh_high = LSHIndex(threshold=1.0)
        assert lsh_high.threshold == 1.0

    def test_lsh_total_permutations_limit(self):
        """Test that total permutations don't exceed maximum."""
        # Should raise error if total exceeds 256
        with pytest.raises(ValueError):
            LSHIndex(threshold=0.8, num_bands=64, rows_per_band=5)


class TestLSHAddAndQuery:
    """Test adding rules and querying the LSH index."""

    def test_add_single_rule(self):
        """Test adding a single rule to index."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        minhash = MinHashSignature(num_perm=128)
        signature = minhash.create_signature(rule)

        lsh = LSHIndex(threshold=0.8)
        lsh.add(rule, signature)

        assert len(lsh) == 1

    def test_add_multiple_rules(self):
        """Test adding multiple rules to index."""
        rules = [
            parse_rule(f'alert tcp any any -> any 80 (content:"test{i}"; msg:"T{i}"; sid:{i};)')
            for i in range(1, 6)
        ]

        minhash = MinHashSignature(num_perm=128)
        lsh = LSHIndex(threshold=0.8)

        for rule in rules:
            sig = minhash.create_signature(rule)
            lsh.add(rule, sig)

        assert len(lsh) == 5

    def test_query_returns_candidates(self):
        """Test querying index returns candidate rules."""
        rule1 = parse_rule('alert tcp any any -> any 80 (content:"malicious"; msg:"M1"; sid:1;)')
        rule2 = parse_rule('alert tcp any any -> any 80 (content:"malicious"; msg:"M2"; sid:2;)')
        rule3 = parse_rule('alert udp any any -> any 53 (content:"benign"; msg:"B"; sid:3;)')

        minhash = MinHashSignature(num_perm=128)

        sig1 = minhash.create_signature(rule1)
        sig2 = minhash.create_signature(rule2)
        sig3 = minhash.create_signature(rule3)

        lsh = LSHIndex(threshold=0.7)
        lsh.add(rule1, sig1)
        lsh.add(rule2, sig2)
        lsh.add(rule3, sig3)

        # Query with similar rule should find candidates
        candidates = lsh.query(sig1)

        # Should find at least rule1 itself
        assert len(candidates) >= 1

        # Candidates should be (rule, signature) tuples
        for rule, sig in candidates:
            assert rule is not None
            assert isinstance(sig, list)
            assert len(sig) == 128

    def test_query_with_threshold(self):
        """Test querying with similarity threshold filtering."""
        rule1 = parse_rule('alert tcp any any -> any 80 (content:"attack"; msg:"A1"; sid:1;)')
        rule2 = parse_rule('alert tcp any any -> any 80 (content:"attack"; msg:"A2"; sid:2;)')
        rule3 = parse_rule('alert udp any any -> any 53 (content:"different"; msg:"D"; sid:3;)')

        minhash = MinHashSignature(num_perm=128)

        sig1 = minhash.create_signature(rule1)
        sig2 = minhash.create_signature(rule2)
        sig3 = minhash.create_signature(rule3)

        lsh = LSHIndex(threshold=0.7)
        lsh.add(rule1, sig1)
        lsh.add(rule2, sig2)
        lsh.add(rule3, sig3)

        # Query with high threshold
        results = lsh.query_with_threshold(sig1, min_similarity=0.7)

        # Should return (rule, signature, similarity) tuples
        for rule, sig, similarity in results:
            assert rule is not None
            assert isinstance(sig, list)
            assert 0.0 <= similarity <= 1.0
            assert similarity >= 0.7

    def test_query_similar_rules_found(self):
        """Test that similar rules are found in queries."""
        # Create very similar rules
        base_rule = parse_rule(
            'alert tcp any any -> any 80 (content:"exploit"; msg:"Base"; sid:1;)'
        )
        similar_rule = parse_rule(
            'alert tcp any any -> any 80 (content:"exploit"; msg:"Similar"; sid:2;)'
        )

        minhash = MinHashSignature(num_perm=128)

        base_sig = minhash.create_signature(base_rule)
        similar_sig = minhash.create_signature(similar_rule)

        lsh = LSHIndex(threshold=0.7, num_bands=16)
        lsh.add(similar_rule, similar_sig)

        # Query should find the similar rule
        candidates = lsh.query(base_sig)

        # Should find at least one candidate
        assert len(candidates) >= 1

    def test_query_dissimilar_rules_not_found(self):
        """Test that dissimilar rules may not be found (LSH property)."""
        rule1 = parse_rule('alert tcp any any -> any 80 (content:"HTTP"; msg:"Web"; sid:1;)')
        rule2 = parse_rule('alert udp any any -> any 53 (content:"DNS"; msg:"Domain"; sid:2;)')

        minhash = MinHashSignature(num_perm=128)

        sig1 = minhash.create_signature(rule1)
        sig2 = minhash.create_signature(rule2)

        lsh = LSHIndex(threshold=0.9, num_bands=16)  # High threshold
        lsh.add(rule2, sig2)

        # Query with dissimilar rule
        results = lsh.query_with_threshold(sig1, min_similarity=0.9)

        # With high threshold, dissimilar rule should not appear
        # (or have very low similarity if it does)
        assert all(similarity >= 0.9 for _, _, similarity in results)


class TestLSHRemoveAndClear:
    """Test removing rules and clearing the LSH index."""

    def test_remove_existing_rule(self):
        """Test removing a rule from index."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        minhash = MinHashSignature(num_perm=128)
        signature = minhash.create_signature(rule)

        lsh = LSHIndex(threshold=0.8)
        lsh.add(rule, signature)

        assert len(lsh) == 1

        # Remove the rule
        removed = lsh.remove(rule)

        assert removed is True
        assert len(lsh) == 0

    def test_remove_nonexistent_rule(self):
        """Test removing a rule that doesn't exist."""
        rule1 = parse_rule('alert tcp any any -> any 80 (content:"test1"; msg:"T1"; sid:1;)')
        rule2 = parse_rule('alert tcp any any -> any 443 (content:"test2"; msg:"T2"; sid:2;)')

        minhash = MinHashSignature(num_perm=128)

        sig1 = minhash.create_signature(rule1)

        lsh = LSHIndex(threshold=0.8)
        lsh.add(rule1, sig1)

        # Try to remove different rule
        removed = lsh.remove(rule2)

        assert removed is False
        assert len(lsh) == 1

    def test_remove_twice(self):
        """Test removing same rule twice."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        minhash = MinHashSignature(num_perm=128)
        signature = minhash.create_signature(rule)

        lsh = LSHIndex(threshold=0.8)
        lsh.add(rule, signature)

        # Remove first time
        removed1 = lsh.remove(rule)
        assert removed1 is True

        # Remove second time
        removed2 = lsh.remove(rule)
        assert removed2 is False

    def test_clear_index(self):
        """Test clearing all rules from index."""
        rules = [
            parse_rule(f'alert tcp any any -> any 80 (content:"test{i}"; msg:"T{i}"; sid:{i};)')
            for i in range(1, 11)
        ]

        minhash = MinHashSignature(num_perm=128)
        lsh = LSHIndex(threshold=0.8)

        for rule in rules:
            sig = minhash.create_signature(rule)
            lsh.add(rule, sig)

        assert len(lsh) == 10

        # Clear all
        lsh.clear()

        assert len(lsh) == 0

    def test_query_after_clear(self):
        """Test that queries return empty after clear."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        minhash = MinHashSignature(num_perm=128)
        signature = minhash.create_signature(rule)

        lsh = LSHIndex(threshold=0.8)
        lsh.add(rule, signature)

        lsh.clear()

        # Query should return no candidates
        candidates = lsh.query(signature)
        assert len(candidates) == 0


class TestLSHStatistics:
    """Test LSH index statistics."""

    def test_stats_empty_index(self):
        """Test statistics for empty index."""
        lsh = LSHIndex(threshold=0.8)

        stats = lsh.stats()

        assert stats["num_rules"] == 0
        assert stats["num_bands"] == lsh.num_bands
        assert stats["rows_per_band"] == lsh.rows_per_band
        assert stats["threshold"] == 0.8
        assert stats["non_empty_buckets"] == 0

    def test_stats_with_rules(self):
        """Test statistics with rules in index."""
        rules = [
            parse_rule(f'alert tcp any any -> any 80 (content:"test{i}"; msg:"T{i}"; sid:{i};)')
            for i in range(1, 6)
        ]

        minhash = MinHashSignature(num_perm=128)
        lsh = LSHIndex(threshold=0.8)

        for rule in rules:
            sig = minhash.create_signature(rule)
            lsh.add(rule, sig)

        stats = lsh.stats()

        assert stats["num_rules"] == 5
        assert stats["non_empty_buckets"] > 0
        assert stats["avg_bucket_size"] > 0
        assert stats["max_bucket_size"] > 0

    def test_stats_structure(self):
        """Test that statistics contain expected keys."""
        lsh = LSHIndex(threshold=0.8)

        stats = lsh.stats()

        expected_keys = [
            "num_rules",
            "num_bands",
            "rows_per_band",
            "threshold",
            "non_empty_buckets",
            "avg_bucket_size",
            "max_bucket_size",
        ]

        for key in expected_keys:
            assert key in stats


class TestLSHBanding:
    """Test LSH banding and hashing logic."""

    def test_signature_padding(self):
        """Test that short signatures are padded correctly."""
        lsh = LSHIndex(threshold=0.8, num_bands=16, rows_per_band=8)

        # Short signature (will be padded)
        short_sig = [1, 2, 3]

        # Should not raise error
        bands = lsh._get_bands(short_sig)

        assert len(bands) == 16
        for band in bands:
            assert len(band) == 8

    def test_signature_truncation(self):
        """Test that long signatures are truncated correctly."""
        lsh = LSHIndex(threshold=0.8, num_bands=16, rows_per_band=8)

        # Long signature (will be truncated)
        long_sig = list(range(200))

        # Should not raise error
        bands = lsh._get_bands(long_sig)

        assert len(bands) == 16
        for band in bands:
            assert len(band) == 8

    def test_band_hashing_deterministic(self):
        """Test that band hashing is deterministic."""
        lsh = LSHIndex(threshold=0.8)

        band = [1, 2, 3, 4, 5, 6, 7, 8]

        hash1 = lsh._hash_band(band)
        hash2 = lsh._hash_band(band)

        # Same band should produce same hash
        assert hash1 == hash2

    def test_different_bands_different_hashes(self):
        """Test that different bands produce different hashes."""
        lsh = LSHIndex(threshold=0.8)

        band1 = [1, 2, 3, 4, 5, 6, 7, 8]
        band2 = [1, 2, 3, 4, 5, 6, 7, 9]

        hash1 = lsh._hash_band(band1)
        hash2 = lsh._hash_band(band2)

        # Different bands should (likely) produce different hashes
        assert hash1 != hash2


class TestLSHEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_signature(self):
        """Test handling of empty signature."""
        lsh = LSHIndex(threshold=0.8)

        empty_sig = []

        # Should handle empty signature
        bands = lsh._get_bands(empty_sig)

        # Should be padded to expected length
        assert len(bands) == lsh.num_bands

    def test_single_rule_query(self):
        """Test querying with only one rule in index."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        minhash = MinHashSignature(num_perm=128)
        signature = minhash.create_signature(rule)

        lsh = LSHIndex(threshold=0.8)
        lsh.add(rule, signature)

        # Query with same signature
        candidates = lsh.query(signature)

        # Should find itself
        assert len(candidates) >= 1

    def test_very_high_threshold(self):
        """Test LSH with very high threshold."""
        lsh = LSHIndex(threshold=0.99)

        # Should still work
        assert lsh.threshold == 0.99
        assert len(lsh.buckets) == lsh.num_bands

    def test_very_low_threshold(self):
        """Test LSH with very low threshold."""
        lsh = LSHIndex(threshold=0.1)

        # Should still work
        assert lsh.threshold == 0.1
        assert len(lsh.buckets) == lsh.num_bands

    def test_many_similar_rules(self):
        """Test performance with many similar rules."""
        # Create many similar rules
        rules = [
            parse_rule(f'alert tcp any any -> any 80 (content:"common"; msg:"Rule {i}"; sid:{i};)')
            for i in range(1, 51)
        ]

        minhash = MinHashSignature(num_perm=128)
        lsh = LSHIndex(threshold=0.7)

        for rule in rules:
            sig = minhash.create_signature(rule)
            lsh.add(rule, sig)

        # Query with one signature
        query_sig = minhash.create_signature(rules[0])
        candidates = lsh.query(query_sig)

        # Should find many candidates (similar rules)
        assert len(candidates) > 0

    def test_auto_calculated_bands(self):
        """Test that bands are auto-calculated correctly."""
        # Only specify num_bands
        lsh1 = LSHIndex(threshold=0.8, num_bands=32)
        assert lsh1.num_bands == 32
        assert lsh1.rows_per_band == 128 // 32

        # Only specify rows_per_band
        lsh2 = LSHIndex(threshold=0.8, rows_per_band=16)
        assert lsh2.rows_per_band == 16
        assert lsh2.num_bands == 128 // 16


class TestLSHPracticalUsage:
    """Test LSH in practical similarity search scenarios."""

    def test_find_duplicate_rules(self):
        """Test using LSH to find near-duplicate rules."""
        # Create original and near-duplicate
        original = parse_rule(
            'alert tcp any any -> any 80 (content:"malware"; pcre:"/attack/"; msg:"Original"; sid:1;)'
        )
        duplicate = parse_rule(
            'alert tcp any any -> any 80 (content:"malware"; pcre:"/attack/"; msg:"Duplicate"; sid:2;)'
        )
        different = parse_rule(
            'alert udp any any -> any 53 (content:"benign"; msg:"Different"; sid:3;)'
        )

        minhash = MinHashSignature(num_perm=128)
        lsh = LSHIndex(threshold=0.8)

        # Add to index
        lsh.add(original, minhash.create_signature(original))
        lsh.add(duplicate, minhash.create_signature(duplicate))
        lsh.add(different, minhash.create_signature(different))

        # Query for duplicates of original
        query_sig = minhash.create_signature(original)
        results = lsh.query_with_threshold(query_sig, min_similarity=0.8)

        # Should find the duplicate (and possibly itself)
        assert len(results) >= 1

        # Duplicates should have high similarity
        assert all(sim >= 0.8 for _, _, sim in results)

    def test_batch_similarity_search(self):
        """Test searching for similar rules in a batch."""
        # Create a batch of rules
        rules = [
            parse_rule(
                f'alert tcp any any -> any 80 (content:"pattern{i}"; msg:"Rule {i}"; sid:{i};)'
            )
            for i in range(1, 21)
        ]

        minhash = MinHashSignature(num_perm=128)
        lsh = LSHIndex(threshold=0.7)

        # Index all rules
        for rule in rules:
            sig = minhash.create_signature(rule)
            lsh.add(rule, sig)

        # Search for each rule
        for rule in rules[:5]:  # Test first 5
            query_sig = minhash.create_signature(rule)
            candidates = lsh.query(query_sig)

            # Should find at least itself
            assert len(candidates) >= 1
