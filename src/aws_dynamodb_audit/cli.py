"""Command line entry point.

Exit codes: 0 = nothing to fail on, 1 = a --fail-on rule fired, 2 = bad usage or a
collection error.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from aws_dynamodb_audit import __version__
from aws_dynamodb_audit.pricing import (
    DEFAULT_RCU_HOUR,
    DEFAULT_READ_REQUEST_MILLION,
    DEFAULT_WCU_HOUR,
    DEFAULT_WRITE_REQUEST_MILLION,
    Pricing,
)
from aws_dynamodb_audit.report import render_json, render_text
from aws_dynamodb_audit.rules import RULE_NAMES, SEVERITIES, Config, evaluate

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def _csv(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-dynamodb-audit",
        description=(
            "Audit DynamoDB tables for missing point-in-time recovery, AWS-owned encryption keys, "
            "wasted provisioned capacity, pointless global secondary indexes and absent TTL."
        ),
        epilog="Rules: " + ", ".join(RULE_NAMES),
    )
    p.add_argument("--version", action="version", version=f"aws-dynamodb-audit {__version__}")

    src = p.add_argument_group("source")
    src.add_argument("--profile", help="AWS profile to collect with")
    src.add_argument("--region", help="AWS region to collect from")
    src.add_argument("--table", action="append", default=[], help="audit only this table (repeatable)")
    src.add_argument("--lookback-days", type=int, default=14, help="CloudWatch window (default 14)")
    src.add_argument("--from-json", metavar="FILE", help="replay a dump instead of calling AWS")
    src.add_argument("--dump-json", metavar="FILE", help="write the collected payload to FILE")
    src.add_argument(
        "--compare-json",
        metavar="FILE",
        help="an older dump, used to measure item-count growth for no-ttl",
    )

    out = p.add_argument_group("output")
    out.add_argument("--format", choices=("text", "json"), default="text")
    out.add_argument("--severity", choices=SEVERITIES, default="low", help="minimum severity to report")
    out.add_argument("--fail-on", type=_csv, default=[], metavar="RULES", help="exit 1 if these fired")
    out.add_argument("--ignore-rule", type=_csv, default=[], metavar="RULES")
    out.add_argument("--ignore-table", type=_csv, default=[], metavar="TABLES")

    thr = p.add_argument_group("thresholds")
    thr.add_argument("--waste-factor", type=float, default=3.0, help="provisioned/consumed ratio (default 3)")
    thr.add_argument("--prod-threshold", type=int, default=10_000, help="item count that means 'production'")
    thr.add_argument("--require-tags", type=_csv, default=[], metavar="KEYS")
    thr.add_argument("--growth-threshold", type=float, default=0.10, help="item growth that trips no-ttl")

    price = p.add_argument_group("pricing")
    price.add_argument("--price-rcu-hour", type=float, default=DEFAULT_RCU_HOUR)
    price.add_argument("--price-wcu-hour", type=float, default=DEFAULT_WCU_HOUR)
    price.add_argument("--price-read-request", type=float, default=DEFAULT_READ_REQUEST_MILLION)
    price.add_argument("--price-write-request", type=float, default=DEFAULT_WRITE_REQUEST_MILLION)
    return p


def _validate_rules(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    for flag, names in (
        ("--fail-on", args.fail_on),
        ("--ignore-rule", args.ignore_rule),
    ):
        unknown = [n for n in names if n not in RULE_NAMES]
        if unknown:
            parser.error(f"{flag}: unknown rule(s) {', '.join(unknown)}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_rules(parser, args)

    if args.from_json and (args.profile or args.region or args.table):
        parser.error("--from-json replays a dump; --profile/--region/--table do not apply")

    from aws_dynamodb_audit import collect as collector

    try:
        if args.from_json:
            payload = collector.load(args.from_json)
        else:
            payload = collector.collect(
                profile=args.profile,
                region=args.region,
                tables=args.table or None,
                lookback_days=args.lookback_days,
            )
    except Exception as exc:  # noqa: BLE001 - a bad profile or dump is a usage error, not a crash
        print(f"aws-dynamodb-audit: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.dump_json:
        collector.dump(payload, args.dump_json)

    if args.compare_json:
        try:
            payload = {**payload, "_compare": collector.load(args.compare_json)}
        except Exception as exc:  # noqa: BLE001
            print(f"aws-dynamodb-audit: --compare-json: {exc}", file=sys.stderr)
            return EXIT_USAGE

    pricing = Pricing(
        rcu_hour=args.price_rcu_hour,
        wcu_hour=args.price_wcu_hour,
        read_request_million=args.price_read_request,
        write_request_million=args.price_write_request,
    )
    cfg = Config(
        pricing=pricing,
        waste_factor=args.waste_factor,
        prod_threshold=args.prod_threshold,
        growth_threshold=args.growth_threshold,
        require_tags=tuple(args.require_tags),
        lookback_days=payload.get("lookback_days") or args.lookback_days,
    )

    findings = evaluate(
        payload,
        cfg,
        ignore_rules=args.ignore_rule,
        ignore_tables=args.ignore_table,
        min_severity=args.severity,
    )

    if args.format == "json":
        sys.stdout.write(render_json(payload, findings, pricing))
    else:
        sys.stdout.write(render_text(payload, findings))

    if args.fail_on and any(f.rule in set(args.fail_on) for f in findings):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
