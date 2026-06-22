# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.

"""
Coverage tests for plugins/registry.py.

Exercises the shared registration guards (registering a class instead of an
instance, registering a non-conforming object), the parser/query register
paths, the unregister methods, and the singleton's double-checked-locking
branch. Real plugin classes are used throughout.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from surinort_ast.core.nodes import Rule
from surinort_ast.plugins import (
    AnalysisPlugin,
    ParserPlugin,
    PluginRegistry,
    QueryPlugin,
    get_registry,
)
from surinort_ast.plugins.registry import _RegistrySingleton

pytestmark = pytest.mark.usefixtures("clean_registry")


class DemoAnalyzer(AnalysisPlugin):
    def analyze(self, rule: Rule) -> dict[str, Any]:
        return {}


class DemoParser(ParserPlugin):
    def create_parser(self, config: Any) -> Any:
        return None


class DemoQuery(QueryPlugin):
    def get_selector_type(self) -> str:
        return "demo"

    def create_selector(self, query: str) -> Any:
        return query


class TestRegistrationGuards:
    def test_registering_a_class_raises(self):
        registry = PluginRegistry()
        with pytest.raises(TypeError, match="must be an instance"):
            registry.register_analyzer("demo", DemoAnalyzer)  # class, not instance

    def test_registering_wrong_type_raises(self):
        registry = PluginRegistry()
        with pytest.raises(TypeError, match="must implement"):
            registry.register_analyzer("demo", object())


class TestParserAndQueryRegistration:
    def test_register_get_unregister_parser(self):
        registry = PluginRegistry()
        registry.register_parser("demo_parser", DemoParser())

        assert registry.get_parser("demo_parser") is not None
        assert "demo_parser" in registry.list_parsers()
        assert registry.unregister_parser("demo_parser") is True
        assert registry.unregister_parser("demo_parser") is False

    def test_register_get_unregister_query(self):
        registry = PluginRegistry()
        registry.register_query("demo_query", DemoQuery())

        assert registry.get_query("demo_query") is not None
        assert "demo_query" in registry.list_queries()
        assert registry.unregister_query("demo_query") is True
        assert registry.unregister_query("demo_query") is False


class TestUnregister:
    def test_unregister_analyzer(self):
        registry = PluginRegistry()
        registry.register_analyzer("demo", DemoAnalyzer())

        assert registry.unregister_analyzer("demo") is True
        assert registry.unregister_analyzer("demo") is False


class TestSingleton:
    def test_get_registry_returns_same_instance(self):
        assert get_registry() is get_registry()

    def test_double_checked_locking_returns_existing_instance(self):
        """If another caller creates the instance while we wait on the lock, the
        inner ``is None`` check must return the already-created instance rather
        than build a second one."""
        _RegistrySingleton._instance = None
        # Hold the lock so a concurrent get() blocks at the inner check after
        # passing the outer (instance is None) check.
        _RegistrySingleton._lock.acquire()
        captured: dict[str, PluginRegistry] = {}

        def worker() -> None:
            captured["registry"] = _RegistrySingleton.get()

        thread = threading.Thread(target=worker)
        thread.start()
        # Give the worker time to read instance==None and block on the lock.
        time.sleep(0.1)

        sentinel = PluginRegistry()
        _RegistrySingleton._instance = sentinel
        _RegistrySingleton._lock.release()

        thread.join(timeout=2)
        assert captured["registry"] is sentinel
