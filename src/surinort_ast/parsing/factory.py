"""
Parser factory for creating parser instances.

This module provides a factory pattern for creating parser instances,
enabling easy swapping of parser implementations and dependency injection.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from ..core.enums import Dialect
from .interfaces import IParser
from .parser_config import ParserConfig

if TYPE_CHECKING:
    # Avoid circular import at runtime
    from .lark_parser import LarkRuleParser


class ParserFactory:
    """
    Factory for creating parser instances.

    This factory allows:
    - Centralized parser creation
    - Easy swapping of default parser implementation
    - Dependency injection support
    - Configuration management

    The factory maintains a registry of parser implementations and creates
    instances based on configuration. By default, it uses LarkRuleParser.

    Examples:
        >>> # Create default parser
        >>> parser = ParserFactory.create()
        >>> rule = parser.parse('alert tcp any any -> any 80 (sid:1;)')

        >>> # Create parser with custom config
        >>> config = ParserConfig.strict()
        >>> parser = ParserFactory.create(config=config)

        >>> # Register custom default parser
        >>> class CustomParser:
        ...     def parse(self, text: str, file_path: str | None = None, line_offset: int = 0):
        ...         ...
        ...     def parse_file(self, path: str | Path, encoding: str = "utf-8", skip_errors: bool = True):
        ...         ...
        ...
        >>> ParserFactory.register_default(CustomParser)
        >>> parser = ParserFactory.create()  # Now uses CustomParser

        >>> # Create parser with specific dialect
        >>> parser = ParserFactory.create(dialect=Dialect.SNORT3)
    """

    _default_parser_class: Any = None

    @classmethod
    def _get_default_parser_class(cls) -> Any:
        """
        Get the default parser class.

        Returns:
            Default parser class (LarkRuleParser unless overridden)
        """
        if cls._default_parser_class is not None:
            return cls._default_parser_class

        # Import here to avoid circular dependency
        from .lark_parser import LarkRuleParser

        return LarkRuleParser

    @classmethod
    def create(
        cls,
        dialect: Dialect = Dialect.SURICATA,
        strict: bool = False,
        error_recovery: bool = True,
        config: ParserConfig | None = None,
        **kwargs: Any,
    ) -> IParser:
        """
        Create a parser instance with specified configuration.

        This method creates an instance of the registered default parser class
        (LarkRuleParser by default) with the provided configuration.

        Args:
            dialect: Target IDS dialect (Suricata, Snort2, Snort3)
            strict: If True, raise ParseError on any error; if False, return ErrorNode
            error_recovery: Enable error recovery during parsing
            config: Parser configuration with resource limits (default: ParserConfig.default())
            **kwargs: Additional arguments passed to parser constructor

        Returns:
            Configured parser instance implementing IParser protocol

        Examples:
            >>> parser = ParserFactory.create()
            >>> parser = ParserFactory.create(dialect=Dialect.SNORT3, strict=True)
            >>> parser = ParserFactory.create(config=ParserConfig.permissive())
        """
        parser_class = cls._get_default_parser_class()

        # Create instance with provided configuration
        instance = parser_class(
            dialect=dialect,
            strict=strict,
            error_recovery=error_recovery,
            config=config,
            **kwargs,
        )

        # Return as IParser (type system will verify protocol compliance at runtime)
        return cast(IParser, instance)

    @classmethod
    def register_default(cls, parser_class: Any) -> None:
        """
        Register a custom default parser implementation.

        This allows you to replace the default LarkRuleParser with a custom
        implementation throughout the application. The custom parser must
        implement the IParser protocol.

        Args:
            parser_class: Parser class implementing IParser protocol

        Raises:
            TypeError: If parser_class does not implement IParser protocol

        Examples:
            >>> class CustomParser:
            ...     def __init__(self, dialect=Dialect.SURICATA, strict=False, error_recovery=True, config=None):
            ...         self.dialect = dialect
            ...         self.strict = strict
            ...         self.config = config or ParserConfig.default()
            ...
            ...     def parse(self, text: str, file_path: str | None = None, line_offset: int = 0):
            ...         # Custom implementation
            ...         ...
            ...
            ...     def parse_file(self, path: str | Path, encoding: str = "utf-8", skip_errors: bool = True):
            ...         # Custom implementation
            ...         ...
            ...
            >>> ParserFactory.register_default(CustomParser)
            >>> parser = ParserFactory.create()  # Uses CustomParser

        Note:
            The custom parser class should accept the same constructor arguments
            as LarkRuleParser for compatibility with the create() method.
        """
        # Verify that parser_class implements IParser protocol
        # Python's Protocol will check this at type-check time, but we can
        # do a runtime check for the required methods
        required_methods = ["parse", "parse_file"]
        for method_name in required_methods:
            if not hasattr(parser_class, method_name):
                raise TypeError(
                    f"Parser class must implement IParser protocol. Missing method: {method_name}"
                )

        cls._default_parser_class = parser_class

    @classmethod
    def reset_default(cls) -> None:
        """
        Reset the default parser to LarkRuleParser.

        This is useful for testing or when you want to revert to the default
        implementation after registering a custom parser.

        Example:
            >>> ParserFactory.register_default(CustomParser)
            >>> # ... use custom parser ...
            >>> ParserFactory.reset_default()
            >>> parser = ParserFactory.create()  # Back to LarkRuleParser
        """
        cls._default_parser_class = None

    @classmethod
    def create_lark_parser(
        cls,
        dialect: Dialect = Dialect.SURICATA,
        strict: bool = False,
        error_recovery: bool = True,
        config: ParserConfig | None = None,
    ) -> LarkRuleParser:
        """
        Create a LarkRuleParser instance directly.

        This method explicitly creates a LarkRuleParser instance, bypassing
        the factory's default parser registration. Use this when you need
        to ensure you're using the Lark-based parser regardless of factory
        configuration.

        Args:
            dialect: Target IDS dialect
            strict: Strict error mode
            error_recovery: Enable error recovery
            config: Parser configuration

        Returns:
            LarkRuleParser instance

        Example:
            >>> parser = ParserFactory.create_lark_parser(dialect=Dialect.SNORT3)
            >>> isinstance(parser, LarkRuleParser)
            True
        """
        from .lark_parser import LarkRuleParser

        return LarkRuleParser(
            dialect=dialect,
            strict=strict,
            error_recovery=error_recovery,
            config=config,
        )
