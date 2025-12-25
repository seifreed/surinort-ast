"""
Parser configuration with resource limits for DoS prevention.

This module provides configuration classes to enforce resource limits during parsing,
preventing denial-of-service attacks via extremely large or deeply nested rules.

Copyright (c) Marc Rivero López
Licensed under GNU General Public License v3.0
See LICENSE file for full terms

Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ParserConfig:
    """
    Configuration for parser resource limits.

    These limits prevent DoS attacks via extremely large or deeply nested rules.
    Three presets are available: default(), permissive(), and strict().

    Attributes:
        max_rule_length: Maximum rule length in characters (prevents memory exhaustion)
        max_options: Maximum number of options per rule (prevents parsing complexity attacks)
        max_nesting_depth: Maximum nesting depth for lists/negations (prevents stack overflow)
        timeout_seconds: Parse timeout in seconds; 0 = no timeout (prevents infinite loops)
        max_input_size: Maximum total input size in bytes (prevents memory exhaustion)

    Examples:
        >>> config = ParserConfig.default()
        >>> config.max_rule_length
        100000

        >>> strict = ParserConfig.strict()
        >>> strict.timeout_seconds
        10.0

        >>> permissive = ParserConfig.permissive()
        >>> permissive.max_input_size
        1000000000
    """

    # Maximum rule length in characters
    max_rule_length: int = 100_000

    # Maximum number of options per rule
    max_options: int = 1000

    # Maximum nesting depth for lists/negations
    max_nesting_depth: int = 50

    # Parse timeout in seconds (0 = no timeout)
    timeout_seconds: float = 30.0

    # Maximum total input size in bytes
    max_input_size: int = 100_000_000  # 100 MB

    def __post_init__(self) -> None:
        """Validate configuration values after initialization."""
        if self.max_rule_length <= 0:
            raise ValueError(f"max_rule_length must be positive, got {self.max_rule_length}")

        if self.max_options <= 0:
            raise ValueError(f"max_options must be positive, got {self.max_options}")

        if self.max_nesting_depth <= 0:
            raise ValueError(f"max_nesting_depth must be positive, got {self.max_nesting_depth}")

        if self.timeout_seconds < 0:
            raise ValueError(f"timeout_seconds must be non-negative, got {self.timeout_seconds}")

        if self.max_input_size <= 0:
            raise ValueError(f"max_input_size must be positive, got {self.max_input_size}")

    @classmethod
    def default(cls) -> ParserConfig:
        """
        Get default configuration (balanced security/performance).

        Suitable for most production use cases with untrusted input.

        Returns:
            ParserConfig with default settings
        """
        return cls()

    @classmethod
    def permissive(cls) -> ParserConfig:
        """
        Get permissive configuration for trusted inputs.

        Use this for processing known-good rules from trusted sources
        or when performance is critical and input is pre-validated.

        Returns:
            ParserConfig with relaxed limits

        Warning:
            Only use with trusted input sources. Permissive mode reduces
            protection against DoS attacks.
        """
        return cls(
            max_rule_length=1_000_000,  # 1 MB per rule
            max_options=10_000,
            max_nesting_depth=100,
            timeout_seconds=0.0,  # No timeout
            max_input_size=1_000_000_000,  # 1 GB
        )

    @classmethod
    def strict(cls) -> ParserConfig:
        """
        Get strict configuration for untrusted inputs.

        Use this for processing rules from unknown or potentially
        malicious sources. Provides maximum protection against
        resource exhaustion attacks.

        Returns:
            ParserConfig with strict limits
        """
        return cls(
            max_rule_length=10_000,  # 10 KB per rule
            max_options=100,
            max_nesting_depth=20,
            timeout_seconds=10.0,
            max_input_size=10_000_000,  # 10 MB
        )

    def validate_rule_length(self, length: int) -> None:
        """
        Validate rule length against configured limit.

        Args:
            length: Rule length in characters

        Raises:
            ValueError: If rule exceeds maximum length
        """
        if length > self.max_rule_length:
            raise ValueError(
                f"Rule exceeds maximum length "
                f"({length:,} > {self.max_rule_length:,} characters). "
                f"This may indicate a malformed rule or DoS attempt."
            )

    def validate_option_count(self, count: int) -> None:
        """
        Validate option count against configured limit.

        Args:
            count: Number of options in rule

        Raises:
            ValueError: If rule exceeds maximum options
        """
        if count > self.max_options:
            raise ValueError(
                f"Rule exceeds maximum options "
                f"({count:,} > {self.max_options:,}). "
                f"This may indicate a malformed rule or DoS attempt."
            )

    def validate_nesting_depth(self, depth: int) -> None:
        """
        Validate nesting depth against configured limit.

        Args:
            depth: Current nesting depth

        Raises:
            ValueError: If nesting exceeds maximum depth
        """
        if depth >= self.max_nesting_depth:
            raise ValueError(
                f"Nesting depth exceeds maximum "
                f"({depth} >= {self.max_nesting_depth}). "
                f"This may indicate a malformed rule or DoS attempt."
            )

    def validate_input_size(self, size: int) -> None:
        """
        Validate input size against configured limit.

        Args:
            size: Input size in bytes

        Raises:
            ValueError: If input exceeds maximum size
        """
        if size > self.max_input_size:
            raise ValueError(
                f"Input exceeds maximum size "
                f"({size:,} > {self.max_input_size:,} bytes). "
                f"This may indicate a DoS attempt."
            )
