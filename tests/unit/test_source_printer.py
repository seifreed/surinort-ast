from surinort_ast import (
    Action,
    CanonicalPrinter,
    SourcePrinter,
    parse_file,
    parse_rule,
    parse_source_file,
)


def test_source_printer_preserves_multiline_rule_and_canonical_printer_normalizes() -> None:
    source = 'alert tcp any any -> any 80 (\n  msg:"x";\n  sid:1;\n)'
    rule = parse_rule(source)

    assert SourcePrinter().print_rule(rule) == source
    assert CanonicalPrinter().print_rule(rule) != source


def test_source_printer_falls_back_for_programmatic_rule() -> None:
    rule = parse_rule('alert tcp any any -> any 80 (msg:"x"; sid:1;)').model_copy(
        update={"raw_text": None}
    )

    assert SourcePrinter().print_rule(rule) == CanonicalPrinter().print_rule(rule)


def test_source_printer_preserves_leading_file_comments(tmp_path) -> None:
    source = '# generated rules\n# keep this note\nalert tcp any any -> any 80 (msg:"x"; sid:1;)\n'
    path = tmp_path / "rules.rules"
    path.write_text(source, encoding="utf-8")

    rule = parse_file(path)[0]

    assert list(rule.comments) == ["generated rules", "keep this note"]
    assert SourcePrinter().print_rule(rule).splitlines() == source.rstrip("\n").splitlines()


def test_streaming_file_parser_keeps_leading_comments(tmp_path) -> None:
    path = tmp_path / "stream.rules"
    path.write_text('# stream note\nalert tcp any any -> any 80 (msg:"x"; sid:1;)\n')

    rule = next(iter(parse_file(path, stream=True)))

    assert list(rule.comments) == ["stream note"]


def test_source_printer_preserves_blank_trivia_before_rule(tmp_path) -> None:
    source = '\n# note\n\nalert tcp any any -> any 80 (msg:"x"; sid:1;)\n'
    path = tmp_path / "trivia.rules"
    path.write_text(source, encoding="utf-8")

    rule = parse_file(path)[0]

    assert SourcePrinter().print_rule(rule) == source.rstrip("\n")


def test_source_file_preserves_full_text_and_replaces_changed_rules(tmp_path) -> None:
    source = (
        "# first\n\n"
        'alert tcp any any -> any 80 (msg:"one"; sid:1;)\n\n'
        "malformed tail\n"
        'alert udp any any -> any 53 (msg:"two"; sid:2;)\n'
        "# trailing\n"
    )
    path = tmp_path / "source.rules"
    path.write_text(source, encoding="utf-8")

    source_file = parse_source_file(path)
    printer = SourcePrinter()

    assert printer.print_file(source_file) == source
    changed = source_file.rules[-1].model_copy(update={"action": Action.DROP})
    changed_file = source_file.model_copy(update={"rules": (*source_file.rules[:-1], changed)})
    rendered = printer.print_file(changed_file)
    assert rendered != source
    assert "# first\n\n" in rendered
    assert "malformed tail\n" in rendered
    assert "# trailing\n" in rendered
