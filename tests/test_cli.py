from __future__ import annotations

import json
import socket

import pytest

from aws_dynamodb_audit.cli import main


@pytest.fixture
def no_network(monkeypatch):
    """Any socket at all during a --from-json run is a bug, so make one impossible."""

    def boom(*args, **kwargs):
        raise AssertionError("--from-json must not touch the network")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)


def run(capsys, *argv) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_text_report_groups_by_table(capsys, fixtures_dir, no_network):
    code, out, _ = run(capsys, "--from-json", str(fixtures_dir / "account.json"))
    assert code == 0
    assert "region=eu-central-1" in out
    assert "tables=4" in out
    for table in ("orders", "sessions", "audit-log", "archive"):
        assert f"\n{table}\n" in out
    assert "Estimated monthly waste: $" in out


def test_clean_payload_says_so(capsys, fixtures_dir, no_network):
    code, out, _ = run(capsys, "--from-json", str(fixtures_dir / "clean.json"))
    assert code == 0
    assert "No findings." in out
    assert "Estimated monthly waste" not in out


def test_json_output_is_parseable_and_carries_pricing(capsys, fixtures_dir, no_network):
    code, out, _ = run(capsys, "--from-json", str(fixtures_dir / "account.json"), "--format", "json")
    assert code == 0
    doc = json.loads(out)
    assert doc["tables_audited"] == 4
    assert doc["region"] == "eu-central-1"
    assert doc["pricing"]["rcu_hour"] == 0.00013
    assert "us-east-1" in doc["pricing_note"]
    assert doc["estimated_monthly_waste_usd"] > 0
    assert {f["rule"] for f in doc["findings"]} >= {"no-pitr", "gsi-projects-all"}


def test_from_json_is_byte_for_byte_reproducible(capsys, fixtures_dir, no_network):
    args = ("--from-json", str(fixtures_dir / "account.json"), "--format", "json")
    _, first, _ = run(capsys, *args)
    _, second, _ = run(capsys, *args)
    assert first == second


def test_fail_on_a_rule_that_fired_exits_1(capsys, fixtures_dir, no_network):
    code, _, _ = run(capsys, "--from-json", str(fixtures_dir / "account.json"), "--fail-on", "no-pitr")
    assert code == 1


def test_fail_on_a_rule_that_did_not_fire_exits_0(capsys, fixtures_dir, no_network):
    code, _, _ = run(capsys, "--from-json", str(fixtures_dir / "clean.json"), "--fail-on", "no-pitr")
    assert code == 0


def test_fail_on_an_unknown_rule_exits_2(fixtures_dir, no_network):
    with pytest.raises(SystemExit) as exc:
        main(["--from-json", str(fixtures_dir / "account.json"), "--fail-on", "no-such-rule"])
    assert exc.value.code == 2


def test_ignore_rule_an_unknown_rule_exits_2(fixtures_dir, no_network):
    with pytest.raises(SystemExit) as exc:
        main(["--from-json", str(fixtures_dir / "account.json"), "--ignore-rule", "nope"])
    assert exc.value.code == 2


def test_fail_on_combines_with_ignore_rule(capsys, fixtures_dir, no_network):
    code, _, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "account.json"),
        "--ignore-rule",
        "no-pitr",
        "--fail-on",
        "no-pitr",
    )
    assert code == 0


def test_ignore_table_drops_the_table_from_the_report(capsys, fixtures_dir, no_network):
    code, out, _ = run(
        capsys, "--from-json", str(fixtures_dir / "account.json"), "--ignore-table", "orders,archive"
    )
    assert code == 0
    assert "\norders\n" not in out
    assert "\narchive\n" not in out
    assert "\naudit-log\n" in out


def test_severity_filter_keeps_only_high(capsys, fixtures_dir, no_network):
    code, out, _ = run(
        capsys, "--from-json", str(fixtures_dir / "account.json"), "--severity", "high", "--format", "json"
    )
    assert code == 0
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"high"}


def test_pricing_overrides_change_the_dollar_figure(capsys, fixtures_dir, no_network):
    args = ("--from-json", str(fixtures_dir / "capacity.json"), "--format", "json")
    _, default, _ = run(capsys, *args)
    _, doubled, _ = run(capsys, *args, "--price-rcu-hour", "0.00026")
    base = json.loads(default)["estimated_monthly_waste_usd"]
    assert json.loads(doubled)["estimated_monthly_waste_usd"] == pytest.approx(base * 2, abs=0.02)


def test_require_tags_turns_on_the_untagged_rule(capsys, fixtures_dir, no_network):
    code, out, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "account.json"),
        "--require-tags",
        "owner,environment",
        "--format",
        "json",
    )
    assert code == 0
    untagged = [f for f in json.loads(out)["findings"] if f["rule"] == "untagged"]
    assert [f["table"] for f in untagged] == ["orders"]


def test_dump_json_writes_the_payload(capsys, fixtures_dir, tmp_path, no_network):
    out_file = tmp_path / "dump.json"
    code, _, _ = run(
        capsys, "--from-json", str(fixtures_dir / "account.json"), "--dump-json", str(out_file)
    )
    assert code == 0
    assert json.loads(out_file.read_text())["tables"][0]["name"] == "orders"


def test_compare_json_switches_no_ttl_to_a_measured_delta(capsys, fixtures_dir, tmp_path, no_network):
    older = json.loads((fixtures_dir / "account.json").read_text())
    for table in older["tables"]:
        table["description"]["ItemCount"] = int(table["description"]["ItemCount"] * 0.4)
    older_file = tmp_path / "older.json"
    older_file.write_text(json.dumps(older))

    code, out, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "account.json"),
        "--compare-json",
        str(older_file),
        "--format",
        "json",
    )
    assert code == 0
    ttl = [f for f in json.loads(out)["findings"] if f["rule"] == "no-ttl"]
    # audit-log is small, so only the measured delta brings it in alongside orders
    assert {f["table"] for f in ttl} == {"orders", "audit-log"}
    assert all(f["detail"]["measured"] is True for f in ttl)


def test_a_missing_dump_is_a_usage_error(capsys, no_network):
    code, _, err = run(capsys, "--from-json", "/nonexistent/dump.json")
    assert code == 2
    assert "aws-dynamodb-audit:" in err


def test_a_json_file_that_is_not_a_dump_is_rejected(capsys, tmp_path, no_network):
    bad = tmp_path / "bad.json"
    bad.write_text('{"hello": "world"}')
    code, _, err = run(capsys, "--from-json", str(bad))
    assert code == 2
    assert "not an aws-dynamodb-audit dump" in err


def test_from_json_rejects_collection_flags(fixtures_dir, no_network):
    with pytest.raises(SystemExit) as exc:
        main(["--from-json", str(fixtures_dir / "account.json"), "--region", "eu-west-1"])
    assert exc.value.code == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "aws-dynamodb-audit" in capsys.readouterr().out


def test_module_entry_point_is_wired():
    """python -m aws_dynamodb_audit and the console script must reach the same main()."""
    from aws_dynamodb_audit import __main__

    assert __main__.main is main
