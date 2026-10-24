"""The rule engine.

Every rule is a plain function over one entry of the collected payload. Nothing in
this module touches the network or imports boto3, which is why the whole suite runs
off JSON fixtures with no AWS account.
"""

from __future__ import annotations

import statistics
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

from aws_dynamodb_audit.pricing import Pricing, usd

GIB = 1024**3

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}
SEVERITIES = ("low", "medium", "high")


@dataclass(frozen=True)
class Finding:
    table: str
    rule: str
    severity: str
    message: str
    detail: dict = field(default_factory=dict)
    estimated_monthly_usd: float | None = None

    def as_dict(self) -> dict:
        out = {
            "table": self.table,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "detail": self.detail,
        }
        if self.estimated_monthly_usd is not None:
            out["estimated_monthly_usd"] = round(self.estimated_monthly_usd, 2)
        return out


@dataclass(frozen=True)
class Config:
    pricing: Pricing = field(default_factory=Pricing)
    waste_factor: float = 3.0
    min_wasted_units: float = 5.0
    prod_threshold: int = 10_000
    prod_size_bytes: int = GIB
    gsi_size_bytes: int = GIB
    idle_gsi_units: float = 0.05
    growth_threshold: float = 0.10
    ttl_size_bytes: int = GIB
    flat_cv: float = 0.35
    headroom: float = 1.2
    require_tags: tuple[str, ...] = ()
    lookback_days: int = 14


# --------------------------------------------------------------------------- #
# payload accessors
# --------------------------------------------------------------------------- #


def _desc(entry: dict) -> dict:
    return entry.get("description") or {}


def billing_mode(entry: dict) -> str:
    """DescribeTable omits BillingModeSummary for tables created before it existed."""
    summary = _desc(entry).get("BillingModeSummary") or {}
    return summary.get("BillingMode") or "PROVISIONED"


def provisioned(entry: dict) -> tuple[float, float]:
    tp = _desc(entry).get("ProvisionedThroughput") or {}
    return float(tp.get("ReadCapacityUnits") or 0), float(tp.get("WriteCapacityUnits") or 0)


def table_size(entry: dict) -> int:
    return int(_desc(entry).get("TableSizeBytes") or 0)


def item_count(entry: dict) -> int:
    return int(_desc(entry).get("ItemCount") or 0)


def indexes(entry: dict) -> list[dict]:
    return list(_desc(entry).get("GlobalSecondaryIndexes") or [])


def _metric_source(entry: dict, index: str | None) -> dict:
    metrics = entry.get("metrics") or {}
    if index is None:
        return metrics.get("table") or {}
    return (metrics.get("gsi") or {}).get(index) or {}


def metric(entry: dict, name: str, stat: str, index: str | None = None) -> float | None:
    series = _metric_source(entry, index).get(name) or {}
    value = series.get(stat)
    return None if value is None else float(value)


def metric_points(entry: dict, name: str, index: str | None = None) -> list[float]:
    series = _metric_source(entry, index).get(name) or {}
    return [float(p) for p in series.get("points") or []]


def _tags(entry: dict) -> dict[str, str]:
    return {t["Key"]: t.get("Value", "") for t in entry.get("tags") or []}


def _human_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TiB"


# --------------------------------------------------------------------------- #
# rules
# --------------------------------------------------------------------------- #


def rule_no_pitr(entry: dict, cfg: Config) -> list[Finding]:
    backups = entry.get("continuous_backups") or {}
    continuous = backups.get("ContinuousBackupsStatus")
    pitr = (backups.get("PointInTimeRecoveryDescription") or {}).get("PointInTimeRecoveryStatus")
    if continuous == "ENABLED" and pitr == "ENABLED":
        return []
    if continuous is None and pitr is None:
        return []
    return [
        Finding(
            table=entry["name"],
            rule="no-pitr",
            severity="high",
            message=(
                "point-in-time recovery is not enabled, so there is no restore window - "
                "this cannot be switched on retroactively"
            ),
            detail={
                "continuous_backups_status": continuous,
                "point_in_time_recovery_status": pitr,
                "item_count": item_count(entry),
            },
        )
    ]


def rule_no_deletion_protection(entry: dict, cfg: Config) -> list[Finding]:
    if _desc(entry).get("DeletionProtectionEnabled"):
        return []
    items, size = item_count(entry), table_size(entry)
    if items < cfg.prod_threshold and size < cfg.prod_size_bytes:
        return []
    reason = (
        f"{items:,} items" if items >= cfg.prod_threshold else f"{_human_bytes(size)} of data"
    )
    return [
        Finding(
            table=entry["name"],
            rule="no-deletion-protection",
            severity="high",
            message=f"deletion protection is off on a table holding {reason}",
            detail={
                "item_count": items,
                "table_size_bytes": size,
                "prod_threshold_items": cfg.prod_threshold,
                "prod_threshold_bytes": cfg.prod_size_bytes,
            },
        )
    ]


def rule_aws_owned_key(entry: dict, cfg: Config) -> list[Finding]:
    sse = _desc(entry).get("SSEDescription") or {}
    sse_type = sse.get("SSEType")
    if sse_type == "KMS":
        return []
    return [
        Finding(
            table=entry["name"],
            rule="aws-owned-key",
            severity="medium",
            message=(
                "table is encrypted with the AWS-owned key, which has no key policy, no grants "
                "and no CloudTrail trail of its own - a customer-managed-key requirement cannot be met"
            ),
            detail={"sse_type": sse_type, "sse_status": sse.get("Status")},
        )
    ]


def _overprovisioned_side(
    entry: dict, cfg: Config, units: float, metric_name: str
) -> tuple[float, float] | None:
    """Return (wasted_units, consumed_avg) when ``units`` is wasteful, else None."""
    consumed = metric(entry, metric_name, "avg")
    if consumed is None or units <= 0:
        return None
    if units <= consumed * cfg.waste_factor:
        return None
    wasted = units - consumed
    if wasted < cfg.min_wasted_units:
        return None
    return wasted, consumed


def rule_overprovisioned_capacity(entry: dict, cfg: Config) -> list[Finding]:
    if billing_mode(entry) != "PROVISIONED":
        return []
    rcu, wcu = provisioned(entry)
    parts: list[str] = []
    detail: dict = {"waste_factor": cfg.waste_factor}
    wasted_cost = 0.0

    read = _overprovisioned_side(entry, cfg, rcu, "ConsumedReadCapacityUnits")
    if read:
        wasted, consumed = read
        ratio = rcu / consumed if consumed else float("inf")
        ratio_txt = f"{ratio:.1f}x" if consumed else "no measured reads"
        parts.append(f"{rcu:g} RCU provisioned against a {consumed:.1f} consumed average ({ratio_txt})")
        detail["read"] = {"provisioned": rcu, "consumed_avg": round(consumed, 2), "wasted": round(wasted, 2)}
        wasted_cost += cfg.pricing.provisioned_monthly(wasted, 0)

    write = _overprovisioned_side(entry, cfg, wcu, "ConsumedWriteCapacityUnits")
    if write:
        wasted, consumed = write
        ratio = wcu / consumed if consumed else float("inf")
        ratio_txt = f"{ratio:.1f}x" if consumed else "no measured writes"
        parts.append(f"{wcu:g} WCU provisioned against a {consumed:.1f} consumed average ({ratio_txt})")
        detail["write"] = {"provisioned": wcu, "consumed_avg": round(consumed, 2), "wasted": round(wasted, 2)}
        wasted_cost += cfg.pricing.provisioned_monthly(0, wasted)

    if not parts:
        return []
    detail["lookback_days"] = cfg.lookback_days
    return [
        Finding(
            table=entry["name"],
            rule="overprovisioned-capacity",
            severity="medium",
            message=f"{'; '.join(parts)} - about {usd(wasted_cost)}/month of unused capacity",
            detail=detail,
            estimated_monthly_usd=wasted_cost,
        )
    ]


def _coefficient_of_variation(points: Sequence[float]) -> float | None:
    usable = [p for p in points if p is not None]
    if len(usable) < 6:
        return None
    mean = statistics.fmean(usable)
    if mean <= 0:
        return None
    return statistics.pstdev(usable) / mean


def rule_ondemand_steady_traffic(entry: dict, cfg: Config) -> list[Finding]:
    if billing_mode(entry) != "PAY_PER_REQUEST":
        return []
    read_cv = _coefficient_of_variation(metric_points(entry, "ConsumedReadCapacityUnits"))
    write_cv = _coefficient_of_variation(metric_points(entry, "ConsumedWriteCapacityUnits"))
    cvs = [cv for cv in (read_cv, write_cv) if cv]
    if not cvs or max(cvs) > cfg.flat_cv:
        return []

    read_avg = metric(entry, "ConsumedReadCapacityUnits", "avg") or 0.0
    write_avg = metric(entry, "ConsumedWriteCapacityUnits", "avg") or 0.0
    read_peak = metric(entry, "ConsumedReadCapacityUnits", "max") or read_avg
    write_peak = metric(entry, "ConsumedWriteCapacityUnits", "max") or write_avg
    if read_avg + write_avg <= 0:
        return []

    seconds_per_month = 3600 * cfg.pricing.as_dict()["hours_per_month"]
    ondemand = cfg.pricing.ondemand_monthly(read_avg * seconds_per_month, write_avg * seconds_per_month)
    target_rcu = max(1.0, round(read_peak * cfg.headroom))
    target_wcu = max(1.0, round(write_peak * cfg.headroom))
    prov = cfg.pricing.provisioned_monthly(target_rcu, target_wcu)
    if prov >= ondemand:
        return []

    saving = ondemand - prov
    return [
        Finding(
            table=entry["name"],
            rule="ondemand-steady-traffic",
            severity="low",
            message=(
                f"on-demand traffic is flat (cv {max(cvs):.2f}) and costs about {usd(ondemand)}/month; "
                f"{target_rcu:g} RCU / {target_wcu:g} WCU provisioned with "
                f"{round((cfg.headroom - 1) * 100)}% headroom would cost about {usd(prov)}/month"
            ),
            detail={
                "ondemand_monthly_usd": round(ondemand, 2),
                "provisioned_equivalent_monthly_usd": round(prov, 2),
                "read_avg": round(read_avg, 2),
                "write_avg": round(write_avg, 2),
                "read_peak": round(read_peak, 2),
                "write_peak": round(write_peak, 2),
                "coefficient_of_variation": round(max(cvs), 3),
            },
            estimated_monthly_usd=saving,
        )
    ]


def rule_gsi_projects_all(entry: dict, cfg: Config) -> list[Finding]:
    size = table_size(entry)
    if size < cfg.gsi_size_bytes:
        return []
    out: list[Finding] = []
    for idx in indexes(entry):
        if (idx.get("Projection") or {}).get("ProjectionType") != "ALL":
            continue
        name = idx.get("IndexName", "?")
        idx_size = int(idx.get("IndexSizeBytes") or 0)
        out.append(
            Finding(
                table=entry["name"],
                rule="gsi-projects-all",
                severity="medium",
                message=(
                    f"GSI {name} projects ALL, so every write to the {_human_bytes(size)} base table is "
                    f"replicated in full into the index ({_human_bytes(idx_size)}); switch to KEYS_ONLY "
                    "or INCLUDE with the attributes the query actually reads"
                ),
                detail={
                    "index": name,
                    "projection_type": "ALL",
                    "index_size_bytes": idx_size,
                    "table_size_bytes": size,
                    "size_ratio": round(idx_size / size, 2) if size else None,
                },
            )
        )
    return out


def rule_gsi_idle(entry: dict, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    for idx in indexes(entry):
        name = idx.get("IndexName", "?")
        read = metric(entry, "ConsumedReadCapacityUnits", "avg", index=name)
        write = metric(entry, "ConsumedWriteCapacityUnits", "avg", index=name)
        if read is None and write is None:
            continue
        total = (read or 0.0) + (write or 0.0)
        if total > cfg.idle_gsi_units:
            continue
        idx_size = int(idx.get("IndexSizeBytes") or 0)
        out.append(
            Finding(
                table=entry["name"],
                rule="gsi-idle",
                severity="medium",
                message=(
                    f"GSI {name} consumed {total:.3f} capacity units on average over "
                    f"{cfg.lookback_days}d - it is paid for on every write and read by nobody"
                ),
                detail={
                    "index": name,
                    "read_avg": read,
                    "write_avg": write,
                    "index_size_bytes": idx_size,
                    "lookback_days": cfg.lookback_days,
                },
            )
        )
    return out


def rule_no_ttl(entry: dict, cfg: Config) -> list[Finding]:
    ttl = entry.get("ttl") or {}
    status = ttl.get("TimeToLiveStatus")
    if status in (None, "ENABLED", "ENABLING"):
        return []

    history = ((entry.get("metrics") or {}).get("item_count")) or {}
    first, last = history.get("first"), history.get("last")
    if first is not None and last is not None:
        first, last = float(first), float(last)
        if first <= 0 or last <= first * (1 + cfg.growth_threshold):
            return []
        growth = (last - first) / first
        message = (
            f"TTL is disabled and the item count grew {growth * 100:.0f}% over "
            f"{cfg.lookback_days}d ({first:,.0f} -> {last:,.0f}) - append-only storage with no expiry"
        )
        detail = {
            "ttl_status": status,
            "item_count_first": first,
            "item_count_last": last,
            "growth_fraction": round(growth, 4),
            "measured": True,
        }
    else:
        size = table_size(entry)
        write_avg = metric(entry, "ConsumedWriteCapacityUnits", "avg") or 0.0
        if size < cfg.ttl_size_bytes or write_avg <= 0:
            return []
        message = (
            f"TTL is disabled on a table of {_human_bytes(size)} taking {write_avg:.1f} WCU of sustained "
            "writes; growth is inferred, pass --compare-json <older dump> for a measured delta"
        )
        detail = {
            "ttl_status": status,
            "table_size_bytes": size,
            "write_avg": round(write_avg, 2),
            "measured": False,
        }

    return [Finding(table=entry["name"], rule="no-ttl", severity="low", message=message, detail=detail)]


def rule_no_autoscaling(entry: dict, cfg: Config) -> list[Finding]:
    if billing_mode(entry) != "PROVISIONED":
        return []
    targets = entry.get("autoscaling_targets")
    if targets is None:
        return []
    dims = {t.get("ScalableDimension") for t in targets}
    missing = sorted(
        d
        for d in ("dynamodb:table:ReadCapacityUnits", "dynamodb:table:WriteCapacityUnits")
        if d not in dims
    )
    if not missing:
        return []
    short = ", ".join(d.rsplit(":", 1)[-1] for d in missing)
    return [
        Finding(
            table=entry["name"],
            rule="no-autoscaling",
            severity="low",
            message=(
                f"provisioned mode with no Application Auto Scaling target for {short} - "
                "capacity only ever changes when a human notices"
            ),
            detail={"missing_dimensions": missing, "registered": sorted(d for d in dims if d)},
        )
    ]


def rule_untagged(entry: dict, cfg: Config) -> list[Finding]:
    if not cfg.require_tags:
        return []
    present = _tags(entry)
    missing = [t for t in cfg.require_tags if not present.get(t)]
    if not missing:
        return []
    return [
        Finding(
            table=entry["name"],
            rule="untagged",
            severity="low",
            message=(
                f"missing required tag(s) {', '.join(missing)} - the cost allocation report "
                "cannot attribute this table's spend"
            ),
            detail={"missing": missing, "present": sorted(present)},
        )
    ]


RuleFn = Callable[[dict, Config], list[Finding]]

RULES: dict[str, RuleFn] = {
    "no-pitr": rule_no_pitr,
    "no-deletion-protection": rule_no_deletion_protection,
    "aws-owned-key": rule_aws_owned_key,
    "overprovisioned-capacity": rule_overprovisioned_capacity,
    "ondemand-steady-traffic": rule_ondemand_steady_traffic,
    "gsi-projects-all": rule_gsi_projects_all,
    "gsi-idle": rule_gsi_idle,
    "no-ttl": rule_no_ttl,
    "no-autoscaling": rule_no_autoscaling,
    "untagged": rule_untagged,
}

RULE_NAMES = tuple(RULES)


def evaluate(
    payload: dict,
    cfg: Config,
    *,
    ignore_rules: Iterable[str] = (),
    ignore_tables: Iterable[str] = (),
    min_severity: str = "low",
) -> list[Finding]:
    """Run every enabled rule over every table and return findings in a stable order."""
    skip_rules = set(ignore_rules)
    skip_tables = set(ignore_tables)
    floor = SEVERITY_ORDER[min_severity]
    compare = _compare_index(payload)

    found: list[Finding] = []
    for entry in payload.get("tables") or []:
        name = entry.get("name")
        if not name or name in skip_tables:
            continue
        entry = _with_history(entry, compare.get(name))
        for rule_name, fn in RULES.items():
            if rule_name in skip_rules:
                continue
            for finding in fn(entry, cfg):
                if SEVERITY_ORDER[finding.severity] >= floor:
                    found.append(finding)

    found.sort(key=lambda f: (f.table, f.rule, f.detail.get("index") or ""))
    return found


def _compare_index(payload: dict) -> dict[str, dict]:
    compare = payload.get("_compare") or {}
    return {e["name"]: e for e in compare.get("tables") or [] if e.get("name")}


def _with_history(entry: dict, older: dict | None) -> dict:
    """Fold an older dump's item count into ``metrics.item_count`` for the no-ttl rule."""
    metrics = dict(entry.get("metrics") or {})
    history = dict(metrics.get("item_count") or {})
    if history.get("last") is None:
        history["last"] = item_count(entry)
    if older is not None and history.get("first") is None:
        history["first"] = item_count(older)
    if history.get("first") is None:
        history.pop("first", None)
    metrics["item_count"] = history
    return {**entry, "metrics": metrics}


def waste_total(findings: Iterable[Finding]) -> float:
    return sum(f.estimated_monthly_usd or 0.0 for f in findings)


__all__ = [
    "RULES",
    "RULE_NAMES",
    "SEVERITIES",
    "SEVERITY_ORDER",
    "Config",
    "Finding",
    "evaluate",
    "waste_total",
]
