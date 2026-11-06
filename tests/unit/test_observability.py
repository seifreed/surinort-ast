"""Security and concurrency checks for package logging."""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO, StringIO
from typing import TextIO, cast

import pytest
from typer.testing import CliRunner

import surinort_ast.analysis.engine as engine_module
from surinort_ast import ParseError, Rule, parse_file, parse_rule
from surinort_ast.analysis import EngineVerifier
from surinort_ast.cli import app
from surinort_ast.lsp.server import serve
from surinort_ast.observability import (
    TRACE,
    add_logging_handler,
    configure_logging,
    log_context,
)
from surinort_ast.streaming.parser import StreamParser, stream_parse_file_parallel
from surinort_ast.streaming.processor import TransformProcessor
from surinort_ast.streaming.writers import StreamWriter


@pytest.fixture(autouse=True)
def restore_package_logger():
    package_logger = logging.getLogger("surinort_ast")
    original_handlers = package_logger.handlers[:]
    original_level = package_logger.level
    original_propagate = package_logger.propagate
    yield
    for handler in package_logger.handlers[:]:
        if handler not in original_handlers:
            package_logger.removeHandler(handler)
            handler.close()
    package_logger.handlers[:] = original_handlers
    package_logger.setLevel(original_level)
    package_logger.propagate = original_propagate


def test_json_logs_are_structured_redacted_and_single_line() -> None:
    output = StringIO()
    configure_logging(level="INFO", log_format="json", stream=output)
    logger = logging.getLogger("surinort_ast.test")
    key_begin = "-" * 5 + "BEGIN "
    key_end = "-" * 5

    with log_context(correlation_id="job-42"):
        logger.info(
            "Rejected input token=top-secret\r\nERROR forged",
            extra={"event_name": "input_rejected", "duration_ms": 8},
        )
        logger.info(
            '{"password":"json-secret","api_key":"key-secret",'
            '"client_secret":"client-secret","AWS_SECRET_ACCESS_KEY":"aws-secret",'
            '"AWS_ACCESS_KEY_ID":"aws-id","refreshToken":"refresh-secret",'
            '"session_id":"session-secret","jwt":"jwt-secret"}'
        )
        logger.info(
            f"{key_begin}ENCRYPTED PRIVATE KEY{key_end}private-key-value"
            f"{key_end}END ENCRYPTED PRIVATE KEY{key_end}"
        )
        logger.info(
            f"{key_begin}DSA PRIVATE KEY{key_end}dsa-secret{key_end}END DSA PRIVATE KEY{key_end}"
        )

    assert len(output.getvalue().splitlines()) == 4
    events = [json.loads(line) for line in output.getvalue().splitlines()]
    event = events[0]
    assert event["timestamp"].endswith("Z")
    assert event["level"] == "INFO"
    assert event["service"] == "surinort-ast"
    assert event["component"] == "test"
    assert event["event_name"] == "input_rejected"
    assert event["correlation_id"] == "job-42"
    assert event["duration_ms"] == 8
    assert "top-secret" not in event["message"]
    assert "\\u000d\\u000a" in event["message"]
    assert "json-secret" not in events[1]["message"]
    assert "key-secret" not in events[1]["message"]
    assert "client-secret" not in events[1]["message"]
    assert "aws-secret" not in events[1]["message"]
    assert "aws-id" not in events[1]["message"]
    assert "refresh-secret" not in events[1]["message"]
    assert "session-secret" not in events[1]["message"]
    assert "jwt-secret" not in events[1]["message"]
    assert "private-key-value" not in events[2]["message"]
    assert "dsa-secret" not in events[3]["message"]


def test_levels_context_reset_and_configuration_are_idempotent() -> None:
    output = StringIO()
    configure_logging(level="INFO", log_format="text", stream=output)
    package_logger = logging.getLogger("surinort_ast")
    configure_logging(level="INFO", log_format="text", stream=output)
    assert len([h for h in package_logger.handlers if getattr(h, "_surinort_owned", False)]) == 1

    logger = logging.getLogger("surinort_ast.test")
    logger.debug("hidden")
    with log_context(operation="parse"):
        logger.log(TRACE, "trace detail")
        logger.info("visible")
    logger.info("outside context")

    assert "hidden" not in output.getvalue()
    assert "trace detail" not in output.getvalue()
    assert "visible" in output.getvalue()
    assert "outside context" in output.getvalue()

    structured_text = StringIO()
    configure_logging(level="INFO", log_format="text", stream=structured_text)
    logger.info(
        "line separator\u2028forged line",
        extra={"event_name": "operation_completed", "operation": "parse", "duration_ms": 2},
    )
    text_event = structured_text.getvalue()
    assert len(text_event.splitlines()) == 1
    assert 'event_name="operation_completed"' in text_event
    assert 'operation="parse"' in text_event
    assert "duration_ms=2" in text_event
    assert "\\u2028" in text_event

    configure_logging(level=TRACE, stream=output)
    logger.log(TRACE, "trace enabled")
    assert "trace enabled" in output.getvalue()


def test_context_is_isolated_between_threads() -> None:
    output = StringIO()
    configure_logging(level="INFO", log_format="json", stream=output)
    logger = logging.getLogger("surinort_ast.test")

    def write_event(number: int) -> None:
        with log_context(correlation_id=f"job-{number}"):
            logger.info("work completed", extra={"event_name": "work_completed"})

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(write_event, range(32)))

    events = [json.loads(line) for line in output.getvalue().splitlines()]
    assert len(events) == 32
    assert {event["correlation_id"] for event in events} == {f"job-{i}" for i in range(32)}


def test_exception_text_is_redacted() -> None:
    output = StringIO()
    configure_logging(level="ERROR", log_format="json", stream=output)
    logger = logging.getLogger("surinort_ast.test")

    try:
        raise ValueError("password=hunter2")
    except ValueError:
        logger.exception("unexpected failure", extra={"event_name": "operation_failed"})

    event = json.loads(output.getvalue())
    assert "hunter2" not in event["stack_trace"]
    assert "ValueError" in event["stack_trace"]


def test_destination_failure_does_not_escape_into_callers() -> None:
    class BrokenStream:
        def write(self, _: str) -> int:
            raise OSError("sink unavailable")

        def flush(self) -> None:
            raise OSError("sink unavailable")

    configure_logging(level="INFO", stream=cast(TextIO, BrokenStream()))
    logging.getLogger("surinort_ast.test").info("still running")


def test_application_handler_uses_safe_formatting_and_context() -> None:
    configure_logging(level="INFO", stream=StringIO())
    target = StringIO()
    add_logging_handler(logging.StreamHandler(target), log_format="json")

    with log_context(correlation_id="file-destination-7"):
        logging.getLogger("surinort_ast.test").warning(
            "Rejected token=custom-handler-secret",
            extra={"event_name": "custom_sink_test"},
        )

    event = json.loads(target.getvalue())
    assert event["correlation_id"] == "file-destination-7"
    assert event["event_name"] == "custom_sink_test"
    assert "custom-handler-secret" not in target.getvalue()


def test_environment_configuration_and_invalid_values(monkeypatch: pytest.MonkeyPatch) -> None:
    output = StringIO()
    monkeypatch.setenv("SURINORT_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("SURINORT_LOG_FORMAT", "json")
    configure_logging(stream=output)
    logging.getLogger("surinort_ast.test").debug("environment selected")
    assert json.loads(output.getvalue())["message"] == "environment selected"

    with pytest.raises(ValueError, match="Log level"):
        configure_logging(level="not-a-level", stream=output)
    with pytest.raises(ValueError, match="Log format"):
        configure_logging(level="INFO", log_format="xml", stream=output)
    with pytest.raises(ValueError, match="Log format"):
        add_logging_handler(logging.NullHandler(), log_format="xml")


def test_import_does_not_configure_the_root_logger() -> None:
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import logging; root=logging.getLogger(); before=(root.level, tuple(root.handlers)); "
            "import surinort_ast; assert (root.level, tuple(root.handlers)) == before",
        ],
        capture_output=True,
        check=True,
        text=True,
    )


def test_context_rejects_unrecognized_fields() -> None:
    with (
        pytest.raises(ValueError, match="Unsupported log context fields"),
        log_context(password="must-not-be-context"),
    ):
        pass


def test_cli_options_emit_safe_operation_event() -> None:
    result = CliRunner().invoke(
        app,
        ["--log-level", "INFO", "--log-format", "json", "parse", "-"],
        input='alert tcp any any -> any 80 (msg:"token=do-not-log"; sid:1;)\n',
    )

    assert result.exit_code == 0, result.output
    events = [json.loads(line) for line in result.output.splitlines() if line.startswith("{")]
    completion = next(event for event in events if event["event_name"] == "cli_operation_completed")
    assert completion["operation"] == "cli.parse"
    assert completion["outcome"] == "success"
    assert "do-not-log" not in result.output


def test_cli_failures_emit_metadata_without_error_payload() -> None:
    result = CliRunner().invoke(
        app,
        ["--log-level", "WARNING", "--log-format", "json", "from-json", "-"],
        input='{"token":"must-not-appear-in-log"',
    )

    assert result.exit_code == 1
    events = [json.loads(line) for line in result.output.splitlines() if line.startswith("{")]
    failure = next(event for event in events if event["event_name"] == "cli_operation_failed")
    assert failure["operation"] == "cli.from_json"
    assert failure["error_type"] == "JSONDecodeError"
    assert failure["duration_ms"] >= 0
    assert "must-not-appear-in-log" not in json.dumps(failure)


def test_cli_exit_event_includes_exit_code_without_input_content() -> None:
    result = CliRunner().invoke(
        app,
        ["--log-level", "WARNING", "--log-format", "json", "parse", "-"],
        input="malformed token=private-input\n",
    )

    assert result.exit_code == 1
    events = [json.loads(line) for line in result.output.splitlines() if line.startswith("{")]
    failure = next(event for event in events if event["event_name"] == "cli_operation_failed")
    assert failure["operation"] == "cli.parse"
    assert failure["error_type"] == "CommandExit"
    assert failure["error_code"] == "1"
    assert "private-input" not in json.dumps(failure)


def test_parallel_api_file_parse_emits_parent_summary_without_input_data(tmp_path) -> None:
    output = StringIO()
    configure_logging(level="INFO", log_format="json", stream=output)
    rules_path = tmp_path / "private-rules.rules"
    rules_path.write_text(
        'alert tcp any any -> any 80 (msg:"token=private-value"; sid:10;)\n'
        'alert tcp any any -> any 443 (msg:"second"; sid:11;)\n',
        encoding="utf-8",
    )

    with log_context(correlation_id="batch-10"):
        rules = parse_file(rules_path, workers=2)

    assert len(rules) == 2
    event = json.loads(output.getvalue())
    assert event["event_name"] == "api_file_parse_completed"
    assert event["correlation_id"] == "batch-10"
    assert event["rule_count"] == 2
    assert event["duration_ms"] >= 0
    assert str(rules_path) not in output.getvalue()
    assert "private-value" not in output.getvalue()


def test_cancelled_streams_emit_summary_without_file_data(tmp_path) -> None:
    rules_path = tmp_path / "cancelled-private.rules"
    rule = 'alert tcp any any -> any 80 (msg:"rule"; sid:1;)\n'
    rules_path.write_text(rule * 3, encoding="utf-8")
    streams = (
        StreamParser().stream_file(rules_path),
        stream_parse_file_parallel(rules_path, workers=2, chunk_size=1),
    )

    for event_name, stream in zip(
        ("stream_parse_finished", "parallel_stream_parse_finished"), streams, strict=True
    ):
        output = StringIO()
        configure_logging(level="INFO", log_format="json", stream=output)
        next(stream)
        stream.close()

        event = json.loads(output.getvalue())
        assert event["event_name"] == event_name
        assert event["outcome"] == "cancelled"
        assert event["rule_count"] == 1
        assert event["duration_ms"] >= 0
        assert str(rules_path) not in output.getvalue()


def test_stream_failure_emits_error_summary_without_exception_text(tmp_path) -> None:
    rules_path = tmp_path / "invalid-encoding.rules"
    rules_path.write_bytes(b"\xff")
    output = StringIO()
    configure_logging(level="ERROR", log_format="json", stream=output)

    with pytest.raises(ParseError):
        list(StreamParser().stream_file(rules_path))

    event = json.loads(output.getvalue())
    assert event["level"] == "ERROR"
    assert event["event_name"] == "stream_parse_finished"
    assert event["outcome"] == "failure"
    assert event["error_type"] == "ParseError"
    assert str(rules_path) not in output.getvalue()


def test_writer_footer_failure_is_logged_as_failure_without_output_data(tmp_path) -> None:
    class FooterFailureWriter(StreamWriter):
        def _write_header(self) -> None:
            pass

        def _write_rule(self, _rule: Rule) -> None:
            pass

        def _write_footer(self) -> None:
            raise OSError("token=footer-secret")

    output = StringIO()
    configure_logging(level="ERROR", log_format="json", stream=output)
    output_path = tmp_path / "private-output.rules"

    with pytest.raises(OSError), FooterFailureWriter(output_path):
        pass

    event = json.loads(output.getvalue())
    assert event["event_name"] == "stream_writer_closed"
    assert event["level"] == "ERROR"
    assert event["outcome"] == "failure"
    assert event["error_type"] == "OSError"
    assert event["duration_ms"] >= 0
    assert str(output_path) not in output.getvalue()
    assert "footer-secret" not in output.getvalue()


def test_lsp_engine_request_id_is_in_correlated_log() -> None:
    output = StringIO()
    configure_logging(level="WARNING", log_format="json", stream=output)

    def message(payload: dict[str, object]) -> bytes:
        body = json.dumps(payload, separators=(",", ":")).encode()
        return f"Content-Length: {len(body)}\r\n\r\n".encode() + body

    reader = BytesIO(
        b"".join(
            [
                message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                message(
                    {
                        "jsonrpc": "2.0",
                        "method": "textDocument/didOpen",
                        "params": {
                            "textDocument": {
                                "uri": "file:///private.rules",
                                "text": 'alert tcp any any -> any 80 (msg:"private"; sid:1;)\n',
                            }
                        },
                    }
                ),
                message(
                    {
                        "jsonrpc": "2.0",
                        "id": 42,
                        "method": "surinort/engineValidate",
                        "params": {
                            "textDocument": {"uri": "file:///private.rules"},
                            "command": "missing-engine-for-test {file}",
                        },
                    }
                ),
                message({"jsonrpc": "2.0", "method": "exit"}),
            ]
        )
    )
    transport = BytesIO()

    serve(reader, transport)

    event = json.loads(output.getvalue())
    assert event["event_name"] == "engine_validation_finished"
    assert event["operation"] == "lsp.engine_validation"
    assert event["request_id"] == "42"
    assert event["level"] == "WARNING"
    assert event["status"] == "unavailable"
    assert event["outcome"] == "unavailable"
    assert "private.rules" not in output.getvalue()
    assert b'"id":42' in transport.getvalue()


@pytest.mark.parametrize(
    ("returncode", "status", "level"),
    ((0, "passed", "INFO"), (9, "failed", "WARNING")),
)
def test_engine_logs_status_without_subprocess_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path, returncode: int, status: str, level: str
) -> None:
    output = StringIO()
    configure_logging(level="INFO", log_format="json", stream=output)
    monkeypatch.setattr(engine_module.shutil, "which", lambda _name: "/usr/bin/fake-engine")

    def failed_run(*_args, **_kwargs) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["fake-engine"],
            returncode=returncode,
            stdout="private stdout",
            stderr="token=private-stderr",
        )

    monkeypatch.setattr(engine_module.subprocess, "run", failed_run)
    result = EngineVerifier("fake-engine {file}").verify(tmp_path / "private.rules")

    assert result.status == status
    event = json.loads(output.getvalue())
    assert event["event_name"] == "engine_validation_finished"
    assert event["level"] == level
    assert event["status"] == status
    assert event["returncode"] == returncode
    assert event["duration_ms"] >= 0
    assert "private.rules" not in output.getvalue()
    assert "private stdout" not in output.getvalue()
    assert "private-stderr" not in output.getvalue()


def test_repeated_callback_failures_do_not_create_a_log_storm() -> None:
    output = StringIO()
    configure_logging(level="ERROR", log_format="json", stream=output)

    def fail_transform(_rule: Rule) -> Rule:
        raise RuntimeError("token=callback-secret")

    processor = TransformProcessor(fail_transform)
    rule = parse_rule('alert tcp any any -> any 80 (msg:"test"; sid:20;)')
    for _ in range(20):
        assert processor.process(rule) is None

    events = [json.loads(line) for line in output.getvalue().splitlines()]
    assert len(events) == 1
    assert events[0]["event_name"] == "stream_transform_failed"
    assert events[0]["error_type"] == "RuntimeError"
    assert "callback-secret" not in output.getvalue()
