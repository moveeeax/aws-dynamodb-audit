"""Turn a live AWS account into the plain dict the rule engine eats.

The only module that talks to AWS. boto3 is imported inside ``collect`` so that
``--from-json`` runs, and the whole test suite, never need credentials or the SDK
to be importable at module load.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from aws_dynamodb_audit import SCHEMA_VERSION

METRIC_PERIOD_SECONDS = 3600
CONSUMED_METRICS = ("ConsumedReadCapacityUnits", "ConsumedWriteCapacityUnits")


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _session(profile: str | None, region: str | None):
    import boto3

    return boto3.Session(profile_name=profile, region_name=region)


def _series(points: list[tuple[dt.datetime, float]], period: int) -> dict:
    """Collapse CloudWatch datapoints into the shape the rules read.

    CloudWatch reports ``Sum`` of consumed capacity units over the period, so dividing
    by the period length turns it back into units/second, which is what a provisioned
    capacity number is denominated in.
    """
    values = [v / period for _, v in sorted(points)]
    if not values:
        return {"avg": None, "max": None, "points": []}
    return {
        "avg": sum(values) / len(values),
        "max": max(values),
        "points": [round(v, 6) for v in values],
    }


def _metric_queries(table: str, index_names: list[str]) -> list[dict]:
    queries = []
    for i, name in enumerate(CONSUMED_METRICS):
        queries.append(
            {
                "Id": f"t{i}",
                "Label": json.dumps([None, name]),
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/DynamoDB",
                        "MetricName": name,
                        "Dimensions": [{"Name": "TableName", "Value": table}],
                    },
                    "Period": METRIC_PERIOD_SECONDS,
                    "Stat": "Sum",
                },
                "ReturnData": True,
            }
        )
    for j, index in enumerate(index_names):
        for i, name in enumerate(CONSUMED_METRICS):
            queries.append(
                {
                    "Id": f"g{j}_{i}",
                    "Label": json.dumps([index, name]),
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/DynamoDB",
                            "MetricName": name,
                            "Dimensions": [
                                {"Name": "TableName", "Value": table},
                                {"Name": "GlobalSecondaryIndexName", "Value": index},
                            ],
                        },
                        "Period": METRIC_PERIOD_SECONDS,
                        "Stat": "Sum",
                    },
                    "ReturnData": True,
                }
            )
    return queries


def _fetch_metrics(cw, table: str, index_names: list[str], lookback_days: int) -> dict:
    end = _utcnow()
    start = end - dt.timedelta(days=lookback_days)
    queries = _metric_queries(table, index_names)
    results: list[dict] = []
    # get_metric_data accepts at most 500 queries per call; a table with 20 GSIs needs 42.
    for chunk_start in range(0, len(queries), 100):
        paginator = cw.get_paginator("get_metric_data")
        for page in paginator.paginate(
            MetricDataQueries=queries[chunk_start : chunk_start + 100],
            StartTime=start,
            EndTime=end,
            ScanBy="TimestampAscending",
        ):
            results.extend(page["MetricDataResults"])

    merged: dict[str, list[tuple[dt.datetime, float]]] = {}
    for res in results:
        merged.setdefault(res["Label"], []).extend(zip(res["Timestamps"], res["Values"], strict=True))

    out: dict = {"table": {}, "gsi": {}}
    for label, points in merged.items():
        index, name = json.loads(label)
        series = _series(points, METRIC_PERIOD_SECONDS)
        if index is None:
            out["table"][name] = series
        else:
            out["gsi"].setdefault(index, {})[name] = series
    # A GSI with no datapoints at all is idle, not unknown - give the rule zeros to read.
    for index in index_names:
        bucket = out["gsi"].setdefault(index, {})
        for name in CONSUMED_METRICS:
            bucket.setdefault(name, {"avg": 0.0, "max": 0.0, "points": []})
    return out


def _autoscaling_targets(aas, table: str, index_names: list[str]) -> list[dict]:
    ids = [f"table/{table}"] + [f"table/{table}/index/{i}" for i in index_names]
    targets: list[dict] = []
    paginator = aas.get_paginator("describe_scalable_targets")
    for page in paginator.paginate(ServiceNamespace="dynamodb", ResourceIds=ids):
        for t in page["ScalableTargets"]:
            targets.append(
                {
                    "ResourceId": t["ResourceId"],
                    "ScalableDimension": t["ScalableDimension"],
                    "MinCapacity": t.get("MinCapacity"),
                    "MaxCapacity": t.get("MaxCapacity"),
                }
            )
    return targets


def collect(
    *,
    profile: str | None = None,
    region: str | None = None,
    tables: list[str] | None = None,
    lookback_days: int = 14,
) -> dict:
    """Describe every table (or just ``tables``) and return the audit payload."""
    session = _session(profile, region)
    ddb = session.client("dynamodb")
    cw = session.client("cloudwatch")
    aas = session.client("application-autoscaling")

    names = tables or _list_tables(ddb)
    entries = []
    for name in names:
        description = ddb.describe_table(TableName=name)["Table"]
        index_names = [i["IndexName"] for i in description.get("GlobalSecondaryIndexes") or []]
        entries.append(
            {
                "name": name,
                "description": description,
                "continuous_backups": _continuous_backups(ddb, name),
                "ttl": _ttl(ddb, name),
                "tags": _tags(ddb, description.get("TableArn")),
                "autoscaling_targets": _autoscaling_targets(aas, name, index_names),
                "metrics": _fetch_metrics(cw, name, index_names, lookback_days),
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "region": session.region_name,
        "collected_at": _utcnow().replace(microsecond=0).isoformat(),
        "lookback_days": lookback_days,
        "tables": entries,
    }


def _list_tables(ddb) -> list[str]:
    names: list[str] = []
    for page in ddb.get_paginator("list_tables").paginate():
        names.extend(page["TableNames"])
    return names


def _continuous_backups(ddb, name: str) -> dict:
    from botocore.exceptions import ClientError

    try:
        return ddb.describe_continuous_backups(TableName=name)["ContinuousBackupsDescription"]
    except ClientError as exc:  # pragma: no cover - needs a live account to hit
        if exc.response["Error"]["Code"] in ("TableNotFoundException", "AccessDeniedException"):
            return {}
        raise


def _ttl(ddb, name: str) -> dict:
    return ddb.describe_time_to_live(TableName=name)["TimeToLiveDescription"]


def _tags(ddb, arn: str | None) -> list[dict]:
    if not arn:
        return []
    tags: list[dict] = []
    token = None
    while True:
        kwargs = {"ResourceArn": arn}
        if token:
            kwargs["NextToken"] = token
        page = ddb.list_tags_of_resource(**kwargs)
        tags.extend(page.get("Tags") or [])
        token = page.get("NextToken")
        if not token:
            return tags


def dump(payload: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")


def load(path: str | Path) -> dict:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or "tables" not in payload:
        raise ValueError(f"{path}: not an aws-dynamodb-audit dump (no 'tables' key)")
    return payload
