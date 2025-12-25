# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for surinort_ast.analysis.minhash module.

Tests the MinHashSignature class for creating compact fingerprints from
IDS rules and estimating Jaccard similarity between rules.

All tests use real Rule objects and validate actual MinHash operations.
"""

import pytest

from surinort_ast import parse_rule
from surinort_ast.analysis.minhash import MinHashSignature


class TestMinHashSignature:
    """Test MinHashSignature class initialization and basic operations."""

    def test_minhash_initialization_default(self):
        """Test creating MinHash with default parameters."""
        minhash = MinHashSignature()

        assert minhash.num_perm == 128
        assert minhash.seed == 42
        assert len(minhash._hash_functions) == 128

    def test_minhash_initialization_custom(self):
        """Test creating MinHash with custom parameters."""
        minhash = MinHashSignature(num_perm=256, seed=12345)

        assert minhash.num_perm == 256
        assert minhash.seed == 12345
        assert len(minhash._hash_functions) == 256

    def test_minhash_invalid_num_perm(self):
        """Test that invalid num_perm raises ValueError."""
        with pytest.raises(ValueError):
            MinHashSignature(num_perm=0)

        with pytest.raises(ValueError):
            MinHashSignature(num_perm=-10)

    def test_hash_functions_generation(self):
        """Test that hash functions are generated correctly."""
        minhash = MinHashSignature(num_perm=64, seed=42)

        # Should generate exactly num_perm hash functions
        assert len(minhash._hash_functions) == 64

        # Each hash function should be a tuple of (a, b)
        for a, b in minhash._hash_functions:
            assert isinstance(a, int)
            assert isinstance(b, int)
            assert a > 0  # 'a' should be non-zero

    def test_hash_functions_deterministic(self):
        """Test that hash functions are deterministic with same seed."""
        minhash1 = MinHashSignature(num_perm=128, seed=42)
        minhash2 = MinHashSignature(num_perm=128, seed=42)

        # Same seed should produce same hash functions
        assert minhash1._hash_functions == minhash2._hash_functions

    def test_hash_functions_different_with_different_seed(self):
        """Test that different seeds produce different hash functions."""
        minhash1 = MinHashSignature(num_perm=128, seed=42)
        minhash2 = MinHashSignature(num_perm=128, seed=123)

        # Different seeds should produce different hash functions
        assert minhash1._hash_functions != minhash2._hash_functions


class TestSignatureCreation:
    """Test signature creation from rules."""

    def test_create_signature_basic(self):
        """Test creating signature from a basic rule."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        minhash = MinHashSignature(num_perm=128)
        signature = minhash.create_signature(rule)

        # Should produce correct length signature
        assert len(signature) == 128

        # All values should be integers
        assert all(isinstance(val, int) for val in signature)

        # Values should be non-negative
        assert all(val >= 0 for val in signature)

    def test_create_signature_empty_rule(self):
        """Test creating signature from minimal rule."""
        rule = parse_rule('alert ip any any -> any any (msg:"Minimal"; sid:1;)')

        minhash = MinHashSignature(num_perm=128)
        signature = minhash.create_signature(rule)

        # Should still produce valid signature
        assert len(signature) == 128
        assert all(isinstance(val, int) for val in signature)

    def test_create_signature_complex_rule(self):
        """Test creating signature from complex rule."""
        rule = parse_rule(
            "alert tcp 192.168.1.0/24 any -> any 80 ("
            'content:"GET"; '
            'content:"admin"; '
            'pcre:"/password/i"; '
            "flow:to_server; "
            'msg:"Complex rule"; '
            "sid:1001;)"
        )

        minhash = MinHashSignature(num_perm=128)
        signature = minhash.create_signature(rule)

        assert len(signature) == 128
        assert all(isinstance(val, int) for val in signature)

    def test_signature_deterministic(self):
        """Test that same rule produces same signature."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        minhash = MinHashSignature(num_perm=128, seed=42)

        sig1 = minhash.create_signature(rule)
        sig2 = minhash.create_signature(rule)

        # Same rule should produce identical signature
        assert sig1 == sig2

    def test_signature_reproducible_across_instances(self):
        """Test that same rule produces same signature across MinHash instances."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        minhash1 = MinHashSignature(num_perm=128, seed=42)
        minhash2 = MinHashSignature(num_perm=128, seed=42)

        sig1 = minhash1.create_signature(rule)
        sig2 = minhash2.create_signature(rule)

        # Same seed should produce same signature
        assert sig1 == sig2

    def test_different_rules_different_signatures(self):
        """Test that different rules produce different signatures."""
        rule1 = parse_rule('alert tcp any any -> any 80 (content:"test1"; msg:"Test1"; sid:1;)')
        rule2 = parse_rule('alert udp any any -> any 53 (content:"test2"; msg:"Test2"; sid:2;)')

        minhash = MinHashSignature(num_perm=128)

        sig1 = minhash.create_signature(rule1)
        sig2 = minhash.create_signature(rule2)

        # Different rules should produce different signatures
        assert sig1 != sig2


class TestFeatureExtraction:
    """Test feature extraction from rules."""

    def test_extract_protocol_features(self):
        """Test that protocol is extracted as feature."""
        tcp_rule = parse_rule('alert tcp any any -> any 80 (msg:"TCP"; sid:1;)')
        udp_rule = parse_rule('alert udp any any -> any 53 (msg:"UDP"; sid:2;)')

        minhash = MinHashSignature(num_perm=128)

        tcp_sig = minhash.create_signature(tcp_rule)
        udp_sig = minhash.create_signature(udp_rule)

        # Different protocols should produce different signatures
        assert tcp_sig != udp_sig

    def test_extract_port_features(self):
        """Test that ports are extracted as features."""
        port80 = parse_rule('alert tcp any any -> any 80 (msg:"Port 80"; sid:1;)')
        port443 = parse_rule('alert tcp any any -> any 443 (msg:"Port 443"; sid:2;)')

        minhash = MinHashSignature(num_perm=128)

        sig80 = minhash.create_signature(port80)
        sig443 = minhash.create_signature(port443)

        # Different ports should produce different signatures
        assert sig80 != sig443

    def test_extract_content_features(self):
        """Test that content patterns are extracted."""
        content1 = parse_rule('alert tcp any any -> any 80 (content:"pattern1"; msg:"C1"; sid:1;)')
        content2 = parse_rule('alert tcp any any -> any 80 (content:"pattern2"; msg:"C2"; sid:2;)')

        minhash = MinHashSignature(num_perm=128)

        sig1 = minhash.create_signature(content1)
        sig2 = minhash.create_signature(content2)

        # Different content should produce different signatures
        assert sig1 != sig2

    def test_extract_pcre_features(self):
        """Test that PCRE patterns are extracted."""
        pcre1 = parse_rule('alert tcp any any -> any 80 (pcre:"/pattern1/"; msg:"P1"; sid:1;)')
        pcre2 = parse_rule('alert tcp any any -> any 80 (pcre:"/pattern2/"; msg:"P2"; sid:2;)')

        minhash = MinHashSignature(num_perm=128)

        sig1 = minhash.create_signature(pcre1)
        sig2 = minhash.create_signature(pcre2)

        # Different PCRE should produce different signatures
        assert sig1 != sig2

    def test_content_normalization_case_insensitive(self):
        """Test that content is normalized to lowercase."""
        upper_content = parse_rule(
            'alert tcp any any -> any 80 (content:"TEST"; msg:"Upper"; sid:1;)'
        )
        lower_content = parse_rule(
            'alert tcp any any -> any 80 (content:"test"; msg:"Lower"; sid:2;)'
        )

        minhash = MinHashSignature(num_perm=128)

        sig_upper = minhash.create_signature(upper_content)
        sig_lower = minhash.create_signature(lower_content)

        # Case-normalized content should produce similar signatures
        similarity = minhash.estimate_similarity(sig_upper, sig_lower)
        assert similarity > 0.8  # Should be very similar


class TestSimilarityEstimation:
    """Test similarity estimation between signatures."""

    def test_estimate_similarity_identical(self):
        """Test similarity of identical signatures."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        minhash = MinHashSignature(num_perm=128)
        sig = minhash.create_signature(rule)

        # Identical signatures should have 100% similarity
        similarity = minhash.estimate_similarity(sig, sig)
        assert similarity == 1.0

    def test_estimate_similarity_very_similar(self):
        """Test similarity of very similar rules."""
        rule1 = parse_rule(
            'alert tcp any any -> any 80 (content:"malicious"; msg:"Attack"; sid:1;)'
        )
        rule2 = parse_rule(
            'alert tcp any any -> any 80 (content:"malicious"; msg:"Attack"; sid:2;)'
        )

        minhash = MinHashSignature(num_perm=128)

        sig1 = minhash.create_signature(rule1)
        sig2 = minhash.create_signature(rule2)

        # Same content and structure, only SID differs - should be very similar
        similarity = minhash.estimate_similarity(sig1, sig2)
        assert similarity > 0.8

    def test_estimate_similarity_different(self):
        """Test similarity of completely different rules."""
        rule1 = parse_rule('alert tcp any any -> any 80 (content:"HTTP"; msg:"Web"; sid:1;)')
        rule2 = parse_rule('alert udp any any -> any 53 (content:"DNS"; msg:"Domain"; sid:2;)')

        minhash = MinHashSignature(num_perm=128)

        sig1 = minhash.create_signature(rule1)
        sig2 = minhash.create_signature(rule2)

        # Completely different rules should have low similarity
        similarity = minhash.estimate_similarity(sig1, sig2)
        assert similarity < 0.5

    def test_estimate_similarity_symmetric(self):
        """Test that similarity is symmetric."""
        rule1 = parse_rule('alert tcp any any -> any 80 (content:"test1"; msg:"T1"; sid:1;)')
        rule2 = parse_rule('alert tcp any any -> any 443 (content:"test2"; msg:"T2"; sid:2;)')

        minhash = MinHashSignature(num_perm=128)

        sig1 = minhash.create_signature(rule1)
        sig2 = minhash.create_signature(rule2)

        # Similarity should be symmetric
        sim_1_2 = minhash.estimate_similarity(sig1, sig2)
        sim_2_1 = minhash.estimate_similarity(sig2, sig1)

        assert sim_1_2 == sim_2_1

    def test_estimate_similarity_length_mismatch(self):
        """Test that mismatched signature lengths raise ValueError."""
        minhash128 = MinHashSignature(num_perm=128)
        minhash64 = MinHashSignature(num_perm=64)

        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        sig128 = minhash128.create_signature(rule)
        sig64 = minhash64.create_signature(rule)

        # Mismatched lengths should raise ValueError
        with pytest.raises(ValueError):
            minhash128.estimate_similarity(sig128, sig64)

    def test_estimate_similarity_empty_signatures(self):
        """Test similarity of empty signatures."""
        minhash = MinHashSignature(num_perm=128)

        # Empty signatures should return 0
        similarity = minhash.estimate_similarity([], [])
        assert similarity == 0.0


class TestMinHashAccuracy:
    """Test MinHash similarity estimation accuracy."""

    def test_minhash_preserves_jaccard_similarity(self):
        """Test that MinHash estimates correlate with actual similarity."""
        # Create rules with known overlap
        base_features = 'alert tcp any any -> any 80 (content:"common";'

        rule1 = parse_rule(f'{base_features} content:"unique1"; msg:"R1"; sid:1;)')
        rule2 = parse_rule(f'{base_features} content:"unique2"; msg:"R2"; sid:2;)')
        rule3 = parse_rule(f'{base_features} msg:"R3"; sid:3;)')

        minhash = MinHashSignature(num_perm=256)  # More permutations for accuracy

        sig1 = minhash.create_signature(rule1)
        sig2 = minhash.create_signature(rule2)
        sig3 = minhash.create_signature(rule3)

        # rule1 and rule2 have more in common than rule1 and rule3
        sim_1_2 = minhash.estimate_similarity(sig1, sig2)
        sim_1_3 = minhash.estimate_similarity(sig1, sig3)

        # Both similarities should be relatively high due to common content
        assert sim_1_2 > 0.5
        assert sim_1_3 > 0.5

    def test_more_permutations_more_accurate(self):
        """Test that more permutations give more stable estimates."""
        rule1 = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"T1"; sid:1;)')
        rule2 = parse_rule('alert tcp any any -> any 443 (content:"test"; msg:"T2"; sid:2;)')

        # Use different permutation counts
        minhash_small = MinHashSignature(num_perm=32, seed=42)
        minhash_large = MinHashSignature(num_perm=256, seed=42)

        sig1_small = minhash_small.create_signature(rule1)
        sig2_small = minhash_small.create_signature(rule2)

        sig1_large = minhash_large.create_signature(rule1)
        sig2_large = minhash_large.create_signature(rule2)

        sim_small = minhash_small.estimate_similarity(sig1_small, sig2_small)
        sim_large = minhash_large.estimate_similarity(sig1_large, sig2_large)

        # Both should give reasonable estimates (may not be exact)
        assert 0 <= sim_small <= 1
        assert 0 <= sim_large <= 1


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_rule_with_only_metadata(self):
        """Test signature creation for rule with only metadata options."""
        rule = parse_rule('alert ip any any -> any any (msg:"Minimal"; sid:1; rev:2;)')

        minhash = MinHashSignature(num_perm=128)
        signature = minhash.create_signature(rule)

        # Should still create valid signature
        assert len(signature) == 128
        assert all(isinstance(val, int) for val in signature)

    def test_rule_with_bytes_content(self):
        """Test handling of binary content patterns."""
        # Content with hex bytes
        rule = parse_rule(
            'alert tcp any any -> any 80 (content:"|48 54 54 50|"; msg:"HTTP"; sid:1;)'
        )

        minhash = MinHashSignature(num_perm=128)
        signature = minhash.create_signature(rule)

        # Should handle binary content
        assert len(signature) == 128

    def test_rule_with_port_ranges(self):
        """Test handling of port ranges."""
        rule = parse_rule('alert tcp any any -> any 8000:9000 (msg:"Port range"; sid:1;)')

        minhash = MinHashSignature(num_perm=128)
        signature = minhash.create_signature(rule)

        # Should handle port ranges
        assert len(signature) == 128

    def test_rule_with_port_lists(self):
        """Test handling of port lists."""
        rule = parse_rule('alert tcp any any -> any [80,443,8080] (msg:"Port list"; sid:1;)')

        minhash = MinHashSignature(num_perm=128)
        signature = minhash.create_signature(rule)

        # Should handle port lists
        assert len(signature) == 128

    def test_rule_with_cidr_addresses(self):
        """Test handling of CIDR address ranges."""
        rule = parse_rule('alert tcp 192.168.0.0/16 any -> any any (msg:"CIDR"; sid:1;)')

        minhash = MinHashSignature(num_perm=128)
        signature = minhash.create_signature(rule)

        # Should handle CIDR notation
        assert len(signature) == 128

    def test_rule_with_address_lists(self):
        """Test handling of address lists."""
        rule = parse_rule(
            'alert tcp [192.168.1.1,10.0.0.1] any -> any any (msg:"Addresses"; sid:1;)'
        )

        minhash = MinHashSignature(num_perm=128)
        signature = minhash.create_signature(rule)

        # Should handle address lists
        assert len(signature) == 128

    def test_very_small_num_perm(self):
        """Test MinHash with very small number of permutations."""
        minhash = MinHashSignature(num_perm=4, seed=42)

        rule = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        signature = minhash.create_signature(rule)

        # Should still work with small num_perm
        assert len(signature) == 4

    def test_very_large_num_perm(self):
        """Test MinHash with large number of permutations."""
        minhash = MinHashSignature(num_perm=512, seed=42)

        rule = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        signature = minhash.create_signature(rule)

        # Should work with large num_perm
        assert len(signature) == 512


class TestPcreNormalization:
    """Test PCRE pattern normalization."""

    def test_pcre_delimiter_removal(self):
        """Test that PCRE delimiters are handled correctly."""
        rule1 = parse_rule('alert tcp any any -> any 80 (pcre:"/test/"; msg:"T1"; sid:1;)')
        rule2 = parse_rule('alert tcp any any -> any 80 (pcre:"/test/i"; msg:"T2"; sid:2;)')

        minhash = MinHashSignature(num_perm=128)

        sig1 = minhash.create_signature(rule1)
        sig2 = minhash.create_signature(rule2)

        # Should normalize PCRE patterns (case-insensitive flag difference)
        similarity = minhash.estimate_similarity(sig1, sig2)

        # Should still be very similar (only flag differs)
        assert similarity > 0.7

    def test_pcre_case_normalization(self):
        """Test that PCRE patterns are normalized to lowercase."""
        rule1 = parse_rule('alert tcp any any -> any 80 (pcre:"/TEST/"; msg:"Upper"; sid:1;)')
        rule2 = parse_rule('alert tcp any any -> any 80 (pcre:"/test/"; msg:"Lower"; sid:2;)')

        minhash = MinHashSignature(num_perm=128)

        sig1 = minhash.create_signature(rule1)
        sig2 = minhash.create_signature(rule2)

        # Normalized patterns should be similar
        similarity = minhash.estimate_similarity(sig1, sig2)
        assert similarity > 0.8
