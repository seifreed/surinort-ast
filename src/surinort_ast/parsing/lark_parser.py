"""
Lark-based parser implementation.

This module provides the default IDS rule parser implementation using the Lark
parsing library. It implements the IParser protocol for dependency inversion,
which keeps parsing concerns separate and enables swapping the parser library.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import logging
import platform
import signal
import threading
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from lark import Lark, LarkError, UnexpectedInput, UnexpectedToken
from lark.exceptions import UnexpectedCharacters

from ..core.diagnostics import Diagnostic, DiagnosticLevel
from ..core.enums import Action, Dialect, Protocol
from ..core.location import Location, Position, Span
from ..core.nodes import (
    ErrorNode,
    Header,
    Rule,
    SourceOrigin,
    extract_sid,
)
from ..exceptions import ParseError
from .helpers import normalize_rule_text
from .parser_config import ParserConfig
from .transformer import RuleTransformer

logger = logging.getLogger(__name__)


# ============================================================================
# Lark Parser Implementation
# ============================================================================


class LarkRuleParser:
    """
    Lark-based IDS rule parser implementation.

    This parser implements the IParser protocol using the Lark parsing library.
    It converts text rules into strongly-typed AST nodes. It supports:
    - Multiple dialects (Suricata, Snort2, Snort3)
    - Error recovery with ErrorNode generation
    - Location tracking for all nodes
    - Diagnostic messages for warnings and errors
    - Resource limits for DoS prevention

    The parser uses:
    - LALR(1) parsing strategy for performance
    - Lark grammar defined in grammar.lark
    - RuleTransformer for AST construction
    - ParserConfig for resource limits

    Examples:
        >>> parser = LarkRuleParser()
        >>> rule = parser.parse('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')
        >>> print(rule.action)
        Action.ALERT

        >>> # With custom configuration
        >>> config = ParserConfig.strict()
        >>> parser = LarkRuleParser(config=config)
        >>> rules = parser.parse_file(Path("rules.rules"))
        >>> print(f"Parsed {len(rules)} rules")
    """

    def __init__(
        self,
        dialect: Dialect = Dialect.SURICATA,
        strict: bool = False,
        error_recovery: bool = True,
        config: ParserConfig | None = None,
    ):
        """
        Initialize Lark-based parser.

        Args:
            dialect: Target IDS dialect (Suricata, Snort2, Snort3)
            strict: If True, raise ParseError on any error; if False, return ErrorNode
            error_recovery: Enable error recovery during parsing
            config: Parser configuration with resource limits (default: ParserConfig.default())
        """
        self.dialect = dialect
        self.strict = strict
        self.error_recovery = error_recovery
        self.config = config or ParserConfig.default()
        self._lark_parser: Lark | None = None
        self._grammar_cache: str | None = None

    def _get_grammar(self) -> str:
        """
        Load grammar file.

        Returns:
            Grammar string content

        Raises:
            FileNotFoundError: If grammar file not found
        """
        if self._grammar_cache is not None:
            return self._grammar_cache

        # Grammar file is in the same directory as this module
        grammar_path = Path(__file__).parent / "grammar.lark"

        if not grammar_path.exists():
            raise FileNotFoundError(f"Grammar file not found: {grammar_path}")

        with grammar_path.open(encoding="utf-8") as f:
            self._grammar_cache = f.read()

        return self._grammar_cache

    def _get_parser(self) -> Lark:
        """
        Get or create Lark parser instance.

        The parser is cached after first creation for performance.

        Returns:
            Configured Lark parser
        """
        if self._lark_parser is not None:
            return self._lark_parser

        grammar = self._get_grammar()

        # Create Lark parser with LALR(1) strategy
        self._lark_parser = Lark(
            grammar,
            start="start",
            parser="lalr",  # Fast LALR(1) parser
            # Locations come from token positions in the transformer, not from
            # parse-tree meta, so propagating positions is pure overhead (~20%).
            propagate_positions=False,
            maybe_placeholders=False,  # Strict parsing
            cache=True,  # Cache parser tables
        )

        logger.debug(f"Created Lark parser for {self.dialect.value} dialect")

        return self._lark_parser

    @contextmanager
    def _timeout_context(self) -> Generator[None, None, None]:
        """
        Context manager for parse timeout enforcement.

        Uses platform-appropriate timeout mechanism:
        - Unix/Linux/macOS: signal.setitimer() for sub-second interrupt capability
        - Windows: Threading timer (less precise but cross-platform)

        Only active if timeout_seconds > 0.

        Yields:
            None

        Raises:
            TimeoutError: If parse exceeds timeout_seconds

        Note:
            This timeout mechanism provides best-effort protection against ReDoS.
            It may not interrupt C-extension regex engines in all cases.
            Primary protection comes from regex pattern length bounds in grammar.
        """
        if self.config.timeout_seconds <= 0:
            # No timeout configured
            yield
            return

        is_windows = platform.system() == "Windows"
        timeout_occurred = threading.Event()

        def timeout_handler_signal(signum: int, frame: Any) -> None:
            """Signal-based timeout handler for Unix systems."""
            raise TimeoutError(
                f"Parse timeout after {self.config.timeout_seconds}s. "
                f"This may indicate a ReDoS attack or infinitely complex rule."
            )

        def timeout_handler_thread() -> None:
            """Thread-based timeout handler for Windows systems."""
            timeout_occurred.set()

        on_main_thread = threading.current_thread() is threading.main_thread()
        if (
            not is_windows
            and hasattr(signal, "SIGALRM")
            and hasattr(signal, "setitimer")
            and on_main_thread
        ):
            # Unix-like systems on the main thread: use setitimer(ITIMER_REAL)
            # for sub-second precision. signal.signal() only works on the main
            # thread, so any other thread falls through to the timer-based path
            # below. signal.alarm() truncates to whole seconds, which silently
            # disables any sub-second timeout (e.g. 0.5s -> alarm(0) = no timeout).
            old_handler = signal.signal(signal.SIGALRM, timeout_handler_signal)
            signal.setitimer(signal.ITIMER_REAL, self.config.timeout_seconds)
            try:
                yield
            finally:
                # Cancel timer and restore handler
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, old_handler)
        else:
            # Windows or systems without SIGALRM: use threading timer
            timer = threading.Timer(self.config.timeout_seconds, timeout_handler_thread)
            timer.daemon = True
            timer.start()
            try:
                yield
                # Check if timeout occurred during parsing
                if timeout_occurred.is_set():
                    raise TimeoutError(
                        f"Parse timeout after {self.config.timeout_seconds}s. "
                        f"This may indicate a ReDoS attack or infinitely complex rule."
                    )
            finally:
                timer.cancel()

    def parse(
        self,
        text: str,
        file_path: str | None = None,
        line_offset: int = 0,
    ) -> Rule:
        """
        Parse a single IDS rule from text.

        Args:
            text: Rule text to parse
            file_path: Optional source file path for location tracking
            line_offset: Line number offset for multi-line files

        Returns:
            Parsed Rule AST node, or ErrorNode if parsing fails

        Raises:
            ParseError: If strict mode enabled and parsing fails

        Examples:
            >>> parser = LarkRuleParser()
            >>> rule = parser.parse('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
            >>> print(rule.header.protocol)
            Protocol.TCP
        """
        text = text.strip()
        parse_text = normalize_rule_text(text)

        if not text:
            error = ErrorNode(
                error_type="EmptyInput",
                message="Empty input text",
                location=Location(
                    span=Span(
                        start=Position(line=1, column=1, offset=0),
                        end=Position(line=1, column=1, offset=0),
                    ),
                    file_path=file_path,
                ),
            )

            if self.strict:
                raise ParseError("Empty input text")

            # Return a placeholder Rule with ErrorNode
            return self._create_error_rule(error, text, file_path)

        # Skip comments
        if text.startswith("#"):
            logger.debug(f"Skipping comment line: {text[:50]}")
            error = ErrorNode(
                error_type="Comment",
                message="Comment line, not a rule",
                recovered_text=text,
            )
            return self._create_error_rule(error, text, file_path)

        try:
            # Validate rule length before parsing
            self.config.validate_rule_length(len(parse_text))

            # Get parser
            parser = self._get_parser()

            # Parse with timeout enforcement
            with self._timeout_context():
                # Parse to tree
                tree = parser.parse(parse_text)

                # Transform to AST with config
                transformer = RuleTransformer(
                    file_path=file_path, dialect=self.dialect, config=self.config
                )
                result = transformer.transform(tree)

            # Extract rule (handle both single rule and rule_file)
            if isinstance(result, list):
                if not result:
                    raise ParseError("Parse produced empty result")
                rule = result[0]
            else:
                rule = result

            # Validate result is a Rule
            if not isinstance(rule, Rule):
                raise ParseError(f"Expected Rule, got {type(rule).__name__}")

            # Validate option count after parsing
            self.config.validate_option_count(len(rule.options))

            # Attach source metadata
            rule = self._attach_source_metadata(rule, text, file_path, line_offset)

            # Merge diagnostics from transformer
            if transformer.diagnostics:
                existing_diagnostics = list(rule.diagnostics)
                existing_diagnostics.extend(transformer.diagnostics)
                # Create new Rule with updated diagnostics (immutable)
                rule = rule.model_copy(update={"diagnostics": existing_diagnostics})

            logger.debug(f"Successfully parsed rule: SID={extract_sid(rule)}")

            return rule

        except (UnexpectedInput, UnexpectedToken, UnexpectedCharacters) as e:
            return self._handle_parse_error(e, text, file_path)

        except LarkError as e:
            return self._handle_parse_error(e, text, file_path)

        except Exception as e:
            # Catch-all for unexpected errors
            logger.exception(f"Unexpected error parsing rule: {e}")

            error = ErrorNode(
                error_type="UnexpectedError",
                message=f"Unexpected error: {type(e).__name__}: {e}",
                recovered_text=text,
            )

            if self.strict:
                raise ParseError(str(e)) from e

            return self._create_error_rule(error, text, file_path)

    def parse_file(
        self,
        path: str | Path,
        encoding: str = "utf-8",
        skip_errors: bool = True,
    ) -> list[Rule]:
        """
        Parse IDS rules from a file.

        This method handles multi-line rules, comments, and blank lines.

        Args:
            path: Path to rules file
            encoding: File encoding (default: utf-8)
            skip_errors: If True, skip lines that fail to parse; if False, include ErrorNode

        Returns:
            List of parsed Rule nodes

        Raises:
            FileNotFoundError: If file does not exist
            ParseError: If strict mode enabled and parsing fails

        Examples:
            >>> parser = LarkRuleParser()
            >>> rules = parser.parse_file("rules/emerging-threats.rules")
            >>> valid_rules = [r for r in rules if not isinstance(r, ErrorNode)]
            >>> print(f"Parsed {len(valid_rules)} valid rules")
        """
        file_path = Path(path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        logger.info(f"Parsing rules from {file_path}")

        # Validate file size before reading
        file_size = file_path.stat().st_size
        self.config.validate_input_size(file_size)

        with file_path.open(encoding=encoding) as f:
            lines = f.readlines()

        rules: list[Rule] = []
        current_rule_lines: list[tuple[int, str]] = []

        for line_num, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            # Skip empty lines
            if not line:
                if current_rule_lines:
                    # Parse accumulated multi-line rule
                    rule = self._parse_multiline_rule(
                        current_rule_lines, str(file_path), skip_errors
                    )
                    if rule:
                        rules.append(rule)
                    current_rule_lines = []
                continue

            # Skip comment lines
            if line.startswith("#"):
                continue

            # Honor explicit backslash line continuation (canonical IDS syntax).
            # A trailing backslash continues the line only when the trailing run
            # of backslashes is odd: the final one is the continuation marker and
            # any preceding pairs are escaped literals (e.g. `\\` is one literal
            # backslash, `\\\` is a literal backslash plus a continuation). Only
            # checking the last two characters misclassifies odd runs of 3+.
            trailing_backslashes = len(line) - len(line.rstrip("\\"))
            continuation = trailing_backslashes % 2 == 1
            if continuation:
                line = line[:-1].rstrip()

            # Accumulate rule lines
            current_rule_lines.append((line_num, line))

            if continuation:
                continue

            # A rule is complete once its option block is balanced. Parenthesis
            # depth is tracked outside quoted strings so parens inside content,
            # pcre, or msg values do not affect the count. A line that never
            # opens an option block (depth <= 0) is parsed on its own instead of
            # being merged into the following rule.
            combined = " ".join(rule_line for _, rule_line in current_rule_lines)
            if self._paren_depth(combined) <= 0:
                rule = self._parse_multiline_rule(current_rule_lines, str(file_path), skip_errors)
                if rule:
                    rules.append(rule)
                current_rule_lines = []

        # Handle remaining lines (incomplete rule)
        if current_rule_lines:
            rule = self._parse_multiline_rule(current_rule_lines, str(file_path), skip_errors)
            if rule:
                rules.append(rule)

        logger.info(f"Parsed {len(rules)} rules from {file_path}")

        return rules

    @staticmethod
    def _paren_depth(text: str) -> int:
        """
        Count the net parenthesis depth of an option block, ignoring parens
        inside double-quoted strings (content, pcre, msg, ...).

        Args:
            text: Accumulated rule text

        Returns:
            Net depth of unbalanced parentheses (``> 0`` means the option block
            is still open)
        """
        depth = 0
        in_string = False
        escaped = False
        for char in text:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
        return depth

    def _parse_multiline_rule(
        self,
        lines: Sequence[tuple[int, str]],
        file_path: str,
        skip_errors: bool,
    ) -> Rule | None:
        """
        Parse a multi-line rule.

        Args:
            lines: List of (line_number, line_text) tuples
            file_path: Source file path
            skip_errors: If True, return None on error; if False, return ErrorNode

        Returns:
            Parsed Rule or None
        """
        if not lines:
            return None

        # Combine lines
        full_text = " ".join(line for _, line in lines)
        first_line_num = lines[0][0]

        try:
            rule = self.parse(full_text, file_path=file_path, line_offset=first_line_num - 1)

            # In non-strict mode ``parse`` does not raise on failure; it returns
            # a placeholder rule carrying a PARSE_ERROR diagnostic. Honor
            # skip_errors for that path too, otherwise unparseable lines would
            # silently turn into bogus rules.
            if skip_errors and any(d.code == "PARSE_ERROR" for d in rule.diagnostics):
                return None

            # Update source origin with line number
            if rule and hasattr(rule, "origin") and rule.origin:
                rule = rule.model_copy(
                    update={
                        "origin": SourceOrigin(
                            file_path=file_path,
                            line_number=first_line_num,
                            rule_id=rule.origin.rule_id,
                        )
                    }
                )

            return rule

        except Exception as e:
            logger.warning(f"Failed to parse rule at line {first_line_num}: {e}")

            if skip_errors:
                return None

            error = ErrorNode(
                error_type="ParseError",
                message=str(e),
                recovered_text=full_text,
            )

            return self._create_error_rule(error, full_text, file_path)

    def _handle_parse_error(
        self,
        error: Exception,
        text: str,
        file_path: str | None,
    ) -> Rule:
        """
        Handle parse errors with error recovery.

        Args:
            error: Parse error exception
            text: Original text that failed to parse
            file_path: Source file path

        Returns:
            Rule with ErrorNode

        Raises:
            ParseError: If strict mode enabled
        """
        # Extract error details
        error_msg = str(error)
        expected: list[str] | None = None
        actual: str | None = None
        location: Location | None = None

        # Extract detailed info from UnexpectedInput errors
        if isinstance(error, (UnexpectedInput, UnexpectedToken, UnexpectedCharacters)):
            if hasattr(error, "expected"):
                expected = list(error.expected)
            if hasattr(error, "token"):
                actual = str(error.token)
            if hasattr(error, "line") and hasattr(error, "column"):
                location = Location(
                    span=Span(
                        start=Position(line=error.line, column=error.column, offset=0),
                        end=Position(line=error.line, column=error.column + 1, offset=1),
                    ),
                    file_path=file_path,
                )

        logger.warning(f"Parse error: {error_msg}")

        error_node = ErrorNode(
            error_type=type(error).__name__,
            message=error_msg,
            recovered_text=text,
            expected=expected,
            actual=actual,
            location=location,
        )

        if self.strict:
            raise ParseError(error_msg, location=location) from error

        return self._create_error_rule(error_node, text, file_path)

    def _create_error_rule(
        self,
        error_node: ErrorNode,
        raw_text: str,
        file_path: str | None,
    ) -> Rule:
        """
        Create a placeholder Rule containing an ErrorNode.

        This allows partial AST construction even when parsing fails.

        Args:
            error_node: Error information
            raw_text: Original rule text
            file_path: Source file path

        Returns:
            Rule with minimal valid structure and error diagnostic
        """
        # Create minimal valid header
        dummy_header = Header.wildcard(Protocol.IP)

        # Create diagnostic from error
        diagnostic = Diagnostic(
            level=DiagnosticLevel.ERROR,
            message=error_node.message,
            location=error_node.location,
            code="PARSE_ERROR",
            hint="Check rule syntax for correctness",
        )

        # Create error rule
        return Rule(
            action=Action.ALERT,  # Dummy action
            header=dummy_header,
            options=[],  # Empty options
            dialect=self.dialect,
            raw_text=raw_text,
            diagnostics=[diagnostic],
            location=error_node.location,
        )

    def _attach_source_metadata(
        self,
        rule: Rule,
        raw_text: str,
        file_path: str | None,
        line_offset: int,
    ) -> Rule:
        """
        Attach source metadata to rule.

        Args:
            rule: Parsed rule
            raw_text: Original text
            file_path: Source file path
            line_offset: Line number offset

        Returns:
            Rule with updated metadata
        """
        # Extract SID if available
        sid = extract_sid(rule)

        # Calculate line number
        line_num = None
        start_line = rule.location.span.start.line if rule.location else None
        if start_line is not None:
            line_num = start_line + line_offset

        origin = SourceOrigin(
            file_path=file_path,
            line_number=line_num,
            rule_id=str(sid) if sid else None,
        )

        return rule.model_copy(update={"origin": origin, "raw_text": raw_text})
