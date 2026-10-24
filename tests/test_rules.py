from __future__ import annotations

import copy

import pytest
from conftest import load_fixture

from aws_dynamodb_audit.rules import Config, evaluate, waste_total

GIB = 1024**3


def rules_for(payload: dict, table: str, **kwargs) -> set[str]:
    cfg = kwargs.pop("cfg", Config())
    return {f.rule for f in evaluate(payload, cfg, **kwargs) if f.table == table}


def one(payload: dict, table: str, rule: str, **kwargs):
    cfg = kwargs.pop("cfg", Config())
    hits = [f for f in evaluate(payload, cfg, **kwargs) if f.table == table and f.rule == rule]
    assert hits, f"{rule} did not fire on {table}"
    return hits


# --------------------------------------------------------------------------- #
# durability and encryption
# --------------------------------------------------------------------------- #


def test_clean_table_has_no_findings(clean):
    assert evaluate(clean, Config()) == []


def test_pitr_disabled_fires_and_enabled_does_not():
    payload = load_fixture("pitr_pair.json")
    assert rules_for(payload, "pitr-off") == {"no-pitr"}
    assert rules_for(payload, "pitr-on") == set()


def test_pitr_detail_carries_both_status_fields():
    payload = load_fixture("pitr_pair.json")
    (finding,) = one(payload, "pitr-off", "no-pitr")
    assert finding.severity == "high"
    assert finding.detail["continuous_backups_status"] == "DISABLED"
    assert finding.detail["point_in_time_recovery_status"] == "DISABLED"


def test_missing_backup_payload_is_not_a_finding():
    """An AccessDenied on DescribeContinuousBackups must not read as 'PITR off'."""
    payload = load_fixture("pitr_pair.json")
    payload["tables"] = [t for t in payload["tables"] if t["name"] == "pitr-off"]
    payload["tables"][0]["continuous_backups"] = {}
    assert rules_for(payload, "pitr-off") == set()


def test_aws_owned_key_fires_when_sse_description_absent(account):
    (finding,) = one(account, "audit-log", "aws-owned-key")
    assert finding.detail["sse_type"] is None
    assert rules_for(account, "archive").isdisjoint({"aws-owned-key"})


def test_deletion_protection_respects_prod_threshold(account):
    assert "no-deletion-protection" in rules_for(account, "orders")
    cfg = Config(prod_threshold=10_000_000, prod_size_bytes=100 * GIB)
    assert "no-deletion-protection" not in rules_for(account, "orders", cfg=cfg)


# --------------------------------------------------------------------------- #
# capacity
# --------------------------------------------------------------------------- #


def test_overprovisioned_fires_at_12x_and_not_at_1_25x():
    payload = load_fixture("capacity.json")
    (finding,) = one(payload, "rcu-500-consumed-40", "overprovisioned-capacity")
    assert finding.detail["read"] == {"provisioned": 500.0, "consumed_avg": 40.0, "wasted": 460.0}
    assert "write" not in finding.detail
    # 460 wasted RCU * $0.00013/hour * 730 hours
    assert finding.estimated_monthly_usd == pytest.approx(43.654, abs=0.01)
    assert rules_for(payload, "rcu-50-consumed-40") == set()


def test_overprovisioned_honours_waste_factor():
    payload = load_fixture("capacity.json")
    cfg = Config(waste_factor=1.1)
    assert "overprovisioned-capacity" in rules_for(payload, "rcu-50-consumed-40", cfg=cfg)


def test_overprovisioned_skipped_for_ondemand(account):
    assert "overprovisioned-capacity" not in rules_for(account, "sessions")


def test_zero_traffic_provisioned_table_is_all_waste(account):
    (finding,) = one(account, "archive", "overprovisioned-capacity")
    assert finding.detail["read"]["wasted"] == 1000.0
    assert finding.detail["write"]["wasted"] == 1000.0
    assert finding.estimated_monthly_usd == pytest.approx(569.4, abs=0.01)


def test_small_absolute_waste_is_not_reported():
    payload = load_fixture("capacity.json")
    table = copy.deepcopy(payload["tables"][0])
    table["name"] = "tiny"
    table["description"]["ProvisionedThroughput"]["ReadCapacityUnits"] = 4
    metrics = table["metrics"]["table"]["ConsumedReadCapacityUnits"]
    metrics["avg"] = 0.0
    metrics["points"] = [0.0] * 10
    payload["tables"] = [table]
    assert "overprovisioned-capacity" not in rules_for(payload, "tiny")


def test_ondemand_steady_traffic_names_both_monthly_figures(account):
    (finding,) = one(account, "sessions", "ondemand-steady-traffic")
    detail = finding.detail
    assert detail["ondemand_monthly_usd"] == pytest.approx(98.55, abs=0.01)
    assert detail["provisioned_equivalent_monthly_usd"] == pytest.approx(35.59, abs=0.01)
    assert detail["provisioned_equivalent_monthly_usd"] < detail["ondemand_monthly_usd"]
    assert detail["coefficient_of_variation"] <= 0.35


def test_ondemand_rule_ignores_spiky_traffic(clean):
    assert "ondemand-steady-traffic" not in rules_for(clean, "carts")


def test_autoscaling_missing_both_dimensions(account):
    (finding,) = one(account, "orders", "no-autoscaling")
    assert finding.detail["missing_dimensions"] == [
        "dynamodb:table:ReadCapacityUnits",
        "dynamodb:table:WriteCapacityUnits",
    ]
    assert "no-autoscaling" not in rules_for(account, "audit-log")


# --------------------------------------------------------------------------- #
# indexes
# --------------------------------------------------------------------------- #


def test_only_projection_all_fires():
    payload = load_fixture("projections.json")
    assert rules_for(payload, "proj-all") == {"gsi-projects-all"}
    assert rules_for(payload, "proj-keys-only") == set()
    assert rules_for(payload, "proj-include") == set()


def test_projection_all_reports_the_size_ratio():
    payload = load_fixture("projections.json")
    (finding,) = one(payload, "proj-all", "gsi-projects-all")
    assert finding.detail["index"] == "idx"
    assert finding.detail["size_ratio"] == pytest.approx(0.7)


def test_projection_all_below_size_threshold_is_quiet(clean):
    assert "gsi-projects-all" not in rules_for(clean, "carts")


def test_idle_gsi_is_named(account):
    hits = one(account, "orders", "gsi-idle")
    assert [h.detail["index"] for h in hits] == ["by-status"]


def test_busy_gsi_is_not_idle(account):
    assert "gsi-idle" not in rules_for(account, "archive")


# --------------------------------------------------------------------------- #
# ttl
# --------------------------------------------------------------------------- #


def test_no_ttl_inferred_from_sustained_writes(account):
    (finding,) = one(account, "orders", "no-ttl")
    assert finding.detail["measured"] is False
    assert "--compare-json" in finding.message


def test_no_ttl_uses_a_measured_delta_when_an_older_dump_is_supplied(account):
    older = copy.deepcopy(account)
    for table in older["tables"]:
        table["description"]["ItemCount"] = int(table["description"]["ItemCount"] * 0.5)
    account["_compare"] = older
    (finding,) = one(account, "orders", "no-ttl")
    assert finding.detail["measured"] is True
    assert finding.detail["growth_fraction"] == pytest.approx(1.0, abs=0.01)


def test_flat_item_count_does_not_trip_no_ttl(account):
    account["_compare"] = copy.deepcopy(account)
    assert "no-ttl" not in rules_for(account, "orders")


def test_ttl_enabled_is_quiet(account):
    assert "no-ttl" not in rules_for(account, "archive")


# --------------------------------------------------------------------------- #
# tags, filtering, totals
# --------------------------------------------------------------------------- #


def test_untagged_is_opt_in(account):
    assert "untagged" not in rules_for(account, "orders")
    cfg = Config(require_tags=("owner", "environment"))
    (finding,) = one(account, "orders", "untagged", cfg=cfg)
    assert finding.detail["missing"] == ["environment"]
    assert "untagged" not in rules_for(account, "audit-log", cfg=cfg)


def test_ignore_rule_suppresses_only_its_target(account):
    before = rules_for(account, "orders")
    after = rules_for(account, "orders", ignore_rules=["no-pitr"])
    assert before - after == {"no-pitr"}


def test_ignore_table_suppresses_only_its_target(account):
    findings = evaluate(account, Config(), ignore_tables=["orders"])
    assert {f.table for f in findings} == {"audit-log", "archive", "sessions"}


def test_severity_floor_filters_low_and_medium(account):
    high = evaluate(account, Config(), min_severity="high")
    assert {f.severity for f in high} == {"high"}
    assert {f.rule for f in high} == {"no-pitr", "no-deletion-protection"}


def test_findings_are_sorted_deterministically(account):
    findings = evaluate(account, Config())
    keys = [(f.table, f.rule, f.detail.get("index") or "") for f in findings]
    assert keys == sorted(keys)


def test_waste_total_sums_only_priced_findings(account):
    findings = evaluate(account, Config())
    priced = [f for f in findings if f.estimated_monthly_usd is not None]
    assert len(priced) == 3
    assert waste_total(findings) == pytest.approx(sum(f.estimated_monthly_usd for f in priced))
