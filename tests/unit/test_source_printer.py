from surinort_ast import CanonicalPrinter, SourcePrinter, parse_rule


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
