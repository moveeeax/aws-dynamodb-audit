"""Price constants used to turn capacity waste into a dollar figure.

These are the published us-east-1 DynamoDB Standard-table list prices. Every other
region is more expensive, some of them by 20-30%, so the numbers below are a floor,
not a quote. All four are overridable from the CLI (``--price-rcu-hour`` and friends)
and the value actually used is echoed in the JSON output under ``pricing``.
"""

from __future__ import annotations

from dataclasses import dataclass

HOURS_PER_MONTH = 730

# Provisioned capacity, per unit-hour.
DEFAULT_RCU_HOUR = 0.00013
DEFAULT_WCU_HOUR = 0.00065

# On-demand, per million request units.
DEFAULT_READ_REQUEST_MILLION = 0.125
DEFAULT_WRITE_REQUEST_MILLION = 0.625

PRICING_NOTE = (
    "Prices are us-east-1 DynamoDB Standard list prices "
    f"(provisioned ${DEFAULT_RCU_HOUR}/RCU-hour, ${DEFAULT_WCU_HOUR}/WCU-hour; "
    f"on-demand ${DEFAULT_READ_REQUEST_MILLION}/M read request units, "
    f"${DEFAULT_WRITE_REQUEST_MILLION}/M write request units). "
    "Other regions cost more - override with --price-rcu-hour, --price-wcu-hour, "
    "--price-read-request, --price-write-request."
)


@dataclass(frozen=True)
class Pricing:
    rcu_hour: float = DEFAULT_RCU_HOUR
    wcu_hour: float = DEFAULT_WCU_HOUR
    read_request_million: float = DEFAULT_READ_REQUEST_MILLION
    write_request_million: float = DEFAULT_WRITE_REQUEST_MILLION

    def provisioned_monthly(self, rcu: float, wcu: float) -> float:
        """Monthly cost of holding ``rcu``/``wcu`` provisioned for a full month."""
        return (rcu * self.rcu_hour + wcu * self.wcu_hour) * HOURS_PER_MONTH

    def ondemand_monthly(self, read_units: float, write_units: float) -> float:
        """Monthly cost of serving ``read_units``/``write_units`` request units."""
        return (
            read_units / 1_000_000 * self.read_request_million
            + write_units / 1_000_000 * self.write_request_million
        )

    def as_dict(self) -> dict[str, float]:
        return {
            "rcu_hour": self.rcu_hour,
            "wcu_hour": self.wcu_hour,
            "read_request_million": self.read_request_million,
            "write_request_million": self.write_request_million,
            "hours_per_month": HOURS_PER_MONTH,
        }


def usd(value: float) -> str:
    """Format a dollar amount the way the text report wants it."""
    return f"${value:,.2f}"
