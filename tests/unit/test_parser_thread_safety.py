# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Regression tests for parsing from non-main threads.

The parse timeout context uses ``signal.SIGALRM`` on Unix, but ``signal.signal``
only works on the main thread. Parsing from a worker thread must therefore fall
back to the timer-based timeout instead of crashing with
``ValueError: signal only works in main thread``.
"""

from concurrent.futures import ThreadPoolExecutor

from surinort_ast.core.nodes import Rule
from surinort_ast.parsing.lark_parser import LarkRuleParser

_RULE = 'alert tcp any any -> any 80 (msg:"Thread"; sid:1;)'


def test_parse_succeeds_on_worker_thread():
    """Parsing a valid rule from a worker thread returns a Rule, not an error."""
    parser = LarkRuleParser()

    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(parser.parse, _RULE).result()

    assert isinstance(result, Rule)
    assert result.action.value == "alert"


def test_parse_consistent_main_and_worker_thread():
    """A worker thread yields the same parse result as the main thread."""
    parser = LarkRuleParser()
    main_result = parser.parse(_RULE)

    with ThreadPoolExecutor(max_workers=4) as pool:
        worker_results = list(pool.map(lambda _: parser.parse(_RULE), range(8)))

    for worker_result in worker_results:
        assert isinstance(worker_result, Rule)
        assert worker_result.action == main_result.action
        assert worker_result.header.protocol == main_result.header.protocol
