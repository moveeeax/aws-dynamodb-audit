"""Render findings as a grouped text table or as JSON."""

from __future__ import annotations

import json
import textwrap
from collections.abc import Sequence

from aws_dynamodb_audit import SCHEMA_VERSION, __version__
from aws_dynamodb_audit.pricing import PRICING_NOTE, Pricing, usd
from aws_dynamodb_audit.rules import Finding, waste_total

WRAP_WIDTH = 92


def _group(findings: Sequence[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.table, []).append(f)
    return grouped


def render_text(payload: dict, findings: Sequence[Finding]) -> str:
    tables = payload.get("tables") or []
    lines = [
        f"aws-dynamodb-audit {__version__}  region={payload.get('region') or '-'}  "
        f"tables={len(tables)}  findings={len(findings)}  lookback={payload.get('lookback_days')}d"
    ]
    if not findings:
        lines.append("")
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    rule_width = max(len(f.rule) for f in findings)
    for table, group in _group(findings).items():
        lines.append("")
        lines.append(table)
        for f in group:
            head = f"  {f.severity.upper():<6}  {f.rule:<{rule_width}}  "
            body = textwrap.wrap(f.message, width=WRAP_WIDTH) or [""]
            lines.append(head + body[0])
            lines.extend(" " * len(head) + extra for extra in body[1:])

    total = waste_total(findings)
    if total > 0:
        lines.append("")
        lines.append(f"Estimated monthly waste: {usd(total)}")
    return "\n".join(lines) + "\n"


def render_json(payload: dict, findings: Sequence[Finding], pricing: Pricing) -> str:
    out = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "region": payload.get("region"),
        "collected_at": payload.get("collected_at"),
        "lookback_days": payload.get("lookback_days"),
        "tables_audited": len(payload.get("tables") or []),
        "findings": [f.as_dict() for f in findings],
        "estimated_monthly_waste_usd": round(waste_total(findings), 2),
        "pricing": pricing.as_dict(),
        "pricing_note": PRICING_NOTE,
    }
    return json.dumps(out, indent=2, sort_keys=False) + "\n"
