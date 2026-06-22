"""Shared fixtures for unit tests."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from surinort_ast.plugins import reset_registry


@pytest.fixture
def clean_registry() -> Iterator[None]:
    """Reset the global plugin registry around a test.

    Applied module-wide by the plugin test suites via
    ``pytestmark = pytest.mark.usefixtures("clean_registry")`` so each test
    starts and ends with an empty registry.
    """
    reset_registry()
    yield
    reset_registry()
