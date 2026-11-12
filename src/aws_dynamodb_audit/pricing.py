"""Price constants used to turn capacity waste into a dollar figure.

These are the published us-east-1 DynamoDB Standard-table list prices. Every other
region is more expensive, some of them by 20-30%, so the numbers below are a floor,
not a quote. The throughput and storage prices are overridable from the CLI
(``--price-rcu-hour``, ``--price-storage-gb`` and friends) and the values actually used
are echoed in the JSON output under ``pricing``.
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

# Storage, per GB-month, for the Standard and Standard-IA table classes. The 25 GB
# free tier is per account, not per table, so it is not subtracted here.
DEFAULT_STORAGE_GB_MONTH = 0.25
DEFAULT_STORAGE_GB_MONTH_IA = 0.10

# Standard-IA bills reads and writes about 25% above Standard (us-east-1: $0.00016 vs
# $0.00013 per RCU-hour, $0.00081 vs $0.00065 per WCU-hour, $0.155 vs $0.125 and $0.78
# vs $0.625 per million request units). Applied as a factor so that a regional
# override of the Standard throughput prices carries over to the IA estimate.
IA_THROUGHPUT_FACTOR = 1.25

PRICING_NOTE = (
    "Prices are us-east-1 DynamoDB list prices, Standard table class unless noted "
    f"(provisioned ${DEFAULT_RCU_HOUR}/RCU-hour, ${DEFAULT_WCU_HOUR}/WCU-hour; "
    f"on-demand ${DEFAULT_READ_REQUEST_MILLION}/M read request units, "
    f"${DEFAULT_WRITE_REQUEST_MILLION}/M write request units; "
    f"storage ${DEFAULT_STORAGE_GB_MONTH}/GB-month, ${DEFAULT_STORAGE_GB_MONTH_IA}/GB-month on Standard-IA, "
    f"Standard-IA throughput at {IA_THROUGHPUT_FACTOR}x Standard). "
    "Other regions cost more - override with --price-rcu-hour, --price-wcu-hour, "
    "--price-read-request, --price-write-request, --price-storage-gb, --price-storage-gb-ia."
)


@dataclass(frozen=True)
class Pricing:
    rcu_hour: float = DEFAULT_RCU_HOUR
    wcu_hour: float = DEFAULT_WCU_HOUR
    read_request_million: float = DEFAULT_READ_REQUEST_MILLION
    write_request_million: float = DEFAULT_WRITE_REQUEST_MILLION
    storage_gb_month: float = DEFAULT_STORAGE_GB_MONTH
    storage_gb_month_ia: float = DEFAULT_STORAGE_GB_MONTH_IA
    ia_throughput_factor: float = IA_THROUGHPUT_FACTOR

    def provisioned_monthly(self, rcu: float, wcu: float) -> float:
        """Monthly cost of holding ``rcu``/``wcu`` provisioned for a full month."""
        return (rcu * self.rcu_hour + wcu * self.wcu_hour) * HOURS_PER_MONTH

    def ondemand_monthly(self, read_units: float, write_units: float) -> float:
        """Monthly cost of serving ``read_units``/``write_units`` request units."""
        return (
            read_units / 1_000_000 * self.read_request_million
            + write_units / 1_000_000 * self.write_request_million
        )

    def storage_monthly(self, size_bytes: float, *, infrequent_access: bool = False) -> float:
        """Monthly cost of storing ``size_bytes`` on Standard or Standard-IA."""
        per_gb = self.storage_gb_month_ia if infrequent_access else self.storage_gb_month
        return size_bytes / 1024**3 * per_gb

    def as_dict(self) -> dict[str, float]:
        return {
            "rcu_hour": self.rcu_hour,
            "wcu_hour": self.wcu_hour,
            "read_request_million": self.read_request_million,
            "write_request_million": self.write_request_million,
            "storage_gb_month": self.storage_gb_month,
            "storage_gb_month_ia": self.storage_gb_month_ia,
            "ia_throughput_factor": self.ia_throughput_factor,
            "hours_per_month": HOURS_PER_MONTH,
        }


def usd(value: float) -> str:
    """Format a dollar amount the way the text report wants it."""
    return f"${value:,.2f}"
