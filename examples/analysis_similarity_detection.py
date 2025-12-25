#!/usr/bin/env python3
"""
Rule Similarity Detection Example for surinort-ast

Demonstrates how to detect similar and duplicate IDS rules using MinHash
and LSH algorithms. This example shows:
- MinHash signature generation
- Similarity estimation
- Fast similarity search with LSH
- Duplicate and near-duplicate detection

Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from surinort_ast import parse_rule, print_rule
from surinort_ast.analysis.lsh import LSHIndex
from surinort_ast.analysis.minhash import MinHashSignature


def demonstrate_minhash_basics():
    """
    Demonstrate basic MinHash signature generation and comparison.
    """
    print("=" * 80)
    print("MinHash Basics")
    print("=" * 80)
    print()

    # Create two similar rules
    rule1 = parse_rule(
        'alert tcp any any -> any 80 (content:"malware"; content:"download"; msg:"Malware detected"; sid:1;)'
    )

    rule2 = parse_rule(
        'alert tcp any any -> any 80 (content:"malware"; content:"download"; msg:"Malware found"; sid:2;)'
    )

    # Create a different rule
    rule3 = parse_rule('alert udp any any -> any 53 (content:"DNS"; msg:"DNS query"; sid:3;)')

    print("Rule 1:", print_rule(rule1))
    print("Rule 2:", print_rule(rule2))
    print("Rule 3:", print_rule(rule3))
    print()

    # Create MinHash generator
    minhash = MinHashSignature(num_perm=128, seed=42)

    # Generate signatures
    sig1 = minhash.create_signature(rule1)
    sig2 = minhash.create_signature(rule2)
    sig3 = minhash.create_signature(rule3)

    print(f"Signature length: {len(sig1)} hash values")
    print(f"Example signature (first 10 values): {sig1[:10]}")
    print()

    # Calculate similarities
    sim_1_2 = minhash.estimate_similarity(sig1, sig2)
    sim_1_3 = minhash.estimate_similarity(sig1, sig3)
    sim_2_3 = minhash.estimate_similarity(sig2, sig3)

    print("Similarity Matrix:")
    print(f"  Rule 1 vs Rule 2: {sim_1_2:.2%} (very similar - same content)")
    print(f"  Rule 1 vs Rule 3: {sim_1_3:.2%} (different - different protocol/content)")
    print(f"  Rule 2 vs Rule 3: {sim_2_3:.2%} (different)")
    print()


def demonstrate_duplicate_detection():
    """
    Demonstrate finding duplicate and near-duplicate rules.
    """
    print("=" * 80)
    print("Duplicate Rule Detection")
    print("=" * 80)
    print()

    # Create a rule set with duplicates
    rules = [
        # Original rules
        parse_rule(
            'alert tcp any any -> any 80 (content:"exploit"; pcre:"/attack/"; msg:"Attack 1"; sid:1;)'
        ),
        parse_rule('alert tcp any any -> any 443 (content:"HTTPS"; msg:"SSL traffic"; sid:2;)'),
        parse_rule('alert udp any any -> any 53 (content:"DNS"; msg:"DNS query"; sid:3;)'),
        # Near-duplicate (same detection, different message)
        parse_rule(
            'alert tcp any any -> any 80 (content:"exploit"; pcre:"/attack/"; msg:"Attack detected"; sid:4;)'
        ),
        # Exact duplicate (only SID differs)
        parse_rule('alert tcp any any -> any 443 (content:"HTTPS"; msg:"SSL traffic"; sid:5;)'),
        # Similar but different
        parse_rule(
            'alert tcp any any -> any 80 (content:"exploit"; msg:"Different detection"; sid:6;)'
        ),
    ]

    print(f"Analyzing {len(rules)} rules for duplicates...")
    print()

    # Create MinHash and LSH
    minhash = MinHashSignature(num_perm=128)
    lsh = LSHIndex(threshold=0.8, num_bands=16)

    # Index all rules
    signatures = []
    for rule in rules:
        sig = minhash.create_signature(rule)
        signatures.append(sig)
        lsh.add(rule, sig)

    # Find duplicates for each rule
    duplicates_found = []

    for i, (rule, sig) in enumerate(zip(rules, signatures)):
        # Get SID for reference
        sid = None
        for opt in rule.options:
            if opt.node_type == "SidOption":
                sid = opt.value
                break

        # Query for similar rules
        results = lsh.query_with_threshold(sig, min_similarity=0.8)

        # Filter out self-matches
        similar = [(r, s, sim) for r, s, sim in results if id(r) != id(rule)]

        if similar:
            duplicates_found.append((sid, rule, similar))

    # Report findings
    print(f"Found {len(duplicates_found)} rules with duplicates/near-duplicates:")
    print("-" * 80)

    for sid, rule, similar in duplicates_found:
        print(f"\nRule SID {sid}:")
        print(f"  {print_rule(rule)}")
        print(f"  Similar to {len(similar)} other rule(s):")

        for similar_rule, _, similarity in similar:
            similar_sid = None
            for opt in similar_rule.options:
                if opt.node_type == "SidOption":
                    similar_sid = opt.value
                    break

            print(f"    - SID {similar_sid} (similarity: {similarity:.2%})")
            print(f"      {print_rule(similar_rule)}")

    print()


def demonstrate_lsh_search():
    """
    Demonstrate fast similarity search using LSH.
    """
    print("=" * 80)
    print("Fast Similarity Search with LSH")
    print("=" * 80)
    print()

    # Create a larger rule set
    rules = [
        # Web attack rules
        parse_rule(
            'alert tcp any any -> any 80 (content:"union select"; nocase; msg:"SQL injection 1"; sid:1001;)'
        ),
        parse_rule(
            'alert tcp any any -> any 80 (content:"union select"; content:"from"; nocase; msg:"SQL injection 2"; sid:1002;)'
        ),
        parse_rule(
            'alert tcp any any -> any 80 (content:"select from"; nocase; msg:"SQL injection 3"; sid:1003;)'
        ),
        # XSS rules
        parse_rule(
            'alert tcp any any -> any 80 (content:"<script>"; nocase; msg:"XSS attempt 1"; sid:2001;)'
        ),
        parse_rule(
            'alert tcp any any -> any 80 (content:"<script>"; content:"alert"; nocase; msg:"XSS attempt 2"; sid:2002;)'
        ),
        # Network scanning
        parse_rule('alert tcp any any -> any any (flags:S; msg:"SYN scan 1"; sid:3001;)'),
        parse_rule('alert tcp any any -> any any (flags:S; msg:"SYN scan 2"; sid:3002;)'),
        # Malware
        parse_rule(
            'alert tcp any any -> any 80 (content:".exe"; msg:"Executable download 1"; sid:4001;)'
        ),
        parse_rule(
            'alert tcp any any -> any 80 (content:".exe"; content:"download"; msg:"Executable download 2"; sid:4002;)'
        ),
        # DNS
        parse_rule('alert udp any any -> any 53 (content:"DNS"; msg:"DNS query 1"; sid:5001;)'),
        parse_rule('alert udp any any -> any 53 (content:"DNS"; msg:"DNS query 2"; sid:5002;)'),
    ]

    print(f"Indexing {len(rules)} rules in LSH index...")

    # Create and populate LSH index
    minhash = MinHashSignature(num_perm=128)
    lsh = LSHIndex(threshold=0.75, num_bands=16)

    for rule in rules:
        sig = minhash.create_signature(rule)
        lsh.add(rule, sig)

    # Get index statistics
    stats = lsh.stats()
    print(f"  Rules indexed: {stats['num_rules']}")
    print(f"  Bands: {stats['num_bands']}")
    print(f"  Non-empty buckets: {stats['non_empty_buckets']}")
    print(f"  Average bucket size: {stats['avg_bucket_size']:.2f}")
    print()

    # Query for similar rules
    query_rule = parse_rule(
        'alert tcp any any -> any 80 (content:"union select"; msg:"Test query"; sid:9999;)'
    )
    query_sig = minhash.create_signature(query_rule)

    print("Query Rule:")
    print(f"  {print_rule(query_rule)}")
    print()

    results = lsh.query_with_threshold(query_sig, min_similarity=0.75)

    print(f"Found {len(results)} similar rules:")
    print("-" * 80)

    for rule, sig, similarity in sorted(results, key=lambda x: x[2], reverse=True):
        sid = None
        for opt in rule.options:
            if opt.node_type == "SidOption":
                sid = opt.value
                break

        print(f"\nSID {sid} (similarity: {similarity:.2%}):")
        print(f"  {print_rule(rule)}")

    print()


def demonstrate_similarity_clustering():
    """
    Demonstrate clustering rules by similarity.
    """
    print("=" * 80)
    print("Rule Clustering by Similarity")
    print("=" * 80)
    print()

    # Create rules that should cluster into groups
    rules = [
        # Cluster 1: SQL injection
        parse_rule('alert tcp any any -> any 80 (content:"union"; msg:"SQL 1"; sid:101;)'),
        parse_rule(
            'alert tcp any any -> any 80 (content:"union"; content:"select"; msg:"SQL 2"; sid:102;)'
        ),
        parse_rule('alert tcp any any -> any 80 (content:"select from"; msg:"SQL 3"; sid:103;)'),
        # Cluster 2: XSS
        parse_rule('alert tcp any any -> any 80 (content:"<script"; msg:"XSS 1"; sid:201;)'),
        parse_rule('alert tcp any any -> any 80 (content:"<script>"; msg:"XSS 2"; sid:202;)'),
        # Cluster 3: Malware
        parse_rule('alert tcp any any -> any 80 (content:".exe"; msg:"Malware 1"; sid:301;)'),
        parse_rule('alert tcp any any -> any 80 (content:".dll"; msg:"Malware 2"; sid:302;)'),
        # Cluster 4: SSH
        parse_rule('alert tcp any any -> any 22 (content:"SSH"; msg:"SSH 1"; sid:401;)'),
        parse_rule('alert tcp any any -> any 22 (content:"SSH-2"; msg:"SSH 2"; sid:402;)'),
    ]

    minhash = MinHashSignature(num_perm=128)
    signatures = [minhash.create_signature(rule) for rule in rules]

    # Build similarity matrix
    n = len(rules)
    print(f"Building similarity matrix for {n} rules...")
    print()

    # Find clusters (simple threshold-based)
    threshold = 0.7
    clusters = []
    clustered = set()

    for i in range(n):
        if i in clustered:
            continue

        cluster = [i]
        clustered.add(i)

        for j in range(i + 1, n):
            if j in clustered:
                continue

            similarity = minhash.estimate_similarity(signatures[i], signatures[j])
            if similarity >= threshold:
                cluster.append(j)
                clustered.add(j)

        if len(cluster) > 1:
            clusters.append(cluster)

    # Display clusters
    print(f"Found {len(clusters)} clusters (threshold: {threshold:.0%}):")
    print("-" * 80)

    for cluster_id, cluster in enumerate(clusters, 1):
        print(f"\nCluster {cluster_id} ({len(cluster)} rules):")

        for idx in cluster:
            rule = rules[idx]
            sid = None
            for opt in rule.options:
                if opt.node_type == "SidOption":
                    sid = opt.value
                    break

            print(f"  SID {sid}: {print_rule(rule)}")

    print()


def main():
    """
    Run all similarity detection demonstrations.
    """
    print("\n" + "=" * 80)
    print("IDS Rule Similarity Detection Examples")
    print("=" * 80)
    print()

    demonstrate_minhash_basics()
    print()

    demonstrate_duplicate_detection()
    print()

    demonstrate_lsh_search()
    print()

    demonstrate_similarity_clustering()
    print()

    print("=" * 80)
    print("Analysis Complete")
    print("=" * 80)
    print()
    print("Key Takeaways:")
    print("  1. MinHash provides fast similarity estimation for rules")
    print("  2. LSH enables efficient similarity search in large rule sets")
    print("  3. Duplicate detection helps maintain rule set quality")
    print("  4. Similarity clustering reveals patterns in rule organization")
    print("  5. Threshold tuning affects precision/recall trade-offs")
    print()


if __name__ == "__main__":
    main()
