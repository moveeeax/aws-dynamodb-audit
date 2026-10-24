"""Tests for the collector's pure parts. Nothing here constructs a boto3 client."""

from __future__ import annotations

import datetime as dt
import json

import pytest

from aws_dynamodb_audit import collect


def ts(hour: int) -> dt.datetime:
    return dt.datetime(2026, 10, 24, hour, tzinfo=dt.UTC)


def test_series_converts_period_sums_to_units_per_second():
    # CloudWatch reports consumed capacity as a Sum over the period; a provisioned
    # capacity number is units/second, so the collector has to divide.
    points = [(ts(1), 360_000.0), (ts(2), 720_000.0)]
    series = collect._series(points, 3600)
    assert series["avg"] == pytest.approx(150.0)
    assert series["max"] == pytest.approx(200.0)
    assert series["points"] == [100.0, 200.0]


def test_series_sorts_by_timestamp():
    points = [(ts(5), 3600.0), (ts(1), 7200.0)]
    assert collect._series(points, 3600)["points"] == [2.0, 1.0]


def test_series_of_nothing_is_unknown_not_zero():
    """An empty table-level series means 'no data', which rules must not read as idle."""
    series = collect._series([], 3600)
    assert series == {"avg": None, "max": None, "points": []}


def test_metric_queries_cover_table_and_every_index():
    queries = collect._metric_queries("orders", ["by-customer", "by-status"])
    assert len(queries) == 6
    labels = [json.loads(q["Label"]) for q in queries]
    assert [None, "ConsumedReadCapacityUnits"] in labels
    assert ["by-status", "ConsumedWriteCapacityUnits"] in labels
    assert len({q["Id"] for q in queries}) == 6


def test_index_queries_carry_both_dimensions():
    (query,) = [
        q
        for q in collect._metric_queries("orders", ["by-customer"])
        if json.loads(q["Label"]) == ["by-customer", "ConsumedReadCapacityUnits"]
    ]
    dims = {d["Name"]: d["Value"] for d in query["MetricStat"]["Metric"]["Dimensions"]}
    assert dims == {"TableName": "orders", "GlobalSecondaryIndexName": "by-customer"}
    assert query["MetricStat"]["Stat"] == "Sum"
    assert query["MetricStat"]["Period"] == collect.METRIC_PERIOD_SECONDS


def test_dump_and_load_round_trip(tmp_path):
    payload = {"schema_version": 1, "tables": [{"name": "orders"}]}
    path = tmp_path / "dump.json"
    collect.dump(payload, path)
    assert collect.load(path) == payload
    assert path.read_text().endswith("\n")


def test_dump_serialises_datetimes(tmp_path):
    path = tmp_path / "dump.json"
    collect.dump({"tables": [], "collected_at": ts(9)}, path)
    assert "2026-10-24 09:00:00+00:00" in path.read_text()


def test_load_rejects_a_foreign_json_document(tmp_path):
    path = tmp_path / "other.json"
    path.write_text("[1, 2, 3]")
    with pytest.raises(ValueError, match="not an aws-dynamodb-audit dump"):
        collect.load(path)
