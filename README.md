# aws-dynamodb-audit

[![ci](https://github.com/moveeeax/aws-dynamodb-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-dynamodb-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

DynamoDB does not page you. The table works, it keeps working, and it keeps working at four
times the cost it needs with point-in-time recovery switched off — right up until somebody
runs the wrong delete and learns there is no restore. This reads every table in an account and
says which ones are one accident away from data loss and which ones are quietly burning money.

Every field it checks is already in `DescribeTable`, `DescribeContinuousBackups`,
`DescribeTimeToLive` and CloudWatch. The console just spreads them across five tabs.

## Rules

| rule | severity | fires when |
| --- | --- | --- |
| `no-pitr` | high | continuous backups or PITR is not `ENABLED` — there is no restore window, and it cannot be enabled retroactively |
| `no-deletion-protection` | high | deletion protection is off on a table past `--prod-threshold` items (default 10,000) or 1 GiB |
| `aws-owned-key` | medium | `SSEDescription` is absent or `SSEType` is not `KMS`, so there is no key policy and no CMK |
| `overprovisioned-capacity` | medium | provisioned RCU/WCU exceeds the consumed average by more than `--waste-factor` (default 3x); reports the monthly dollar delta |
| `ondemand-steady-traffic` | low | on-demand with a flat consumed profile whose provisioned equivalent is cheaper; names both monthly figures |
| `gsi-projects-all` | medium | a GSI with `ProjectionType: ALL` on a base table over 1 GiB, with the replicated size spelled out |
| `gsi-idle` | medium | a GSI with effectively zero consumed capacity over the lookback window — paid for on every write, read by nobody |
| `no-ttl` | low | TTL is `DISABLED` on a table that is growing; measured against `--compare-json`, inferred from sustained writes otherwise |
| `no-autoscaling` | low | provisioned mode with no Application Auto Scaling target registered |
| `untagged` | low | missing any key in `--require-tags`, so the cost allocation report cannot attribute the spend |

`untagged` is opt-in: without `--require-tags` it never fires.

## Install

```shell
pip install git+https://github.com/moveeeax/aws-dynamodb-audit
```

Needs Python 3.11+ and `dynamodb:ListTables`, `dynamodb:DescribeTable`,
`dynamodb:DescribeContinuousBackups`, `dynamodb:DescribeTimeToLive`,
`dynamodb:ListTagsOfResource`, `cloudwatch:GetMetricData` and
`application-autoscaling:DescribeScalableTargets`. All read-only — the tool never writes.

## Usage

```shell
aws-dynamodb-audit --profile prod --region eu-central-1
aws-dynamodb-audit --profile prod --dump-json /tmp/ddb.json
aws-dynamodb-audit --from-json /tmp/ddb.json --format json | jq '.findings[] | select(.rule=="no-pitr")'
aws-dynamodb-audit --fail-on no-pitr,aws-owned-key --ignore-table scratch-dev
```

Against the dump in `examples/`:

```console
$ aws-dynamodb-audit --from-json examples/account-dump.json --require-tags owner,environment
aws-dynamodb-audit 0.1.0  region=eu-central-1  tables=4  findings=11  lookback=14d

archive
  MEDIUM  overprovisioned-capacity  1000 RCU provisioned against a 0.0 consumed average (no measured reads); 1000 WCU
                                    provisioned against a 0.0 consumed average (no measured writes) - about $569.40/month of
                                    unused capacity

audit-log
  MEDIUM  aws-owned-key             table is encrypted with the AWS-owned key, which has no key policy, no grants and no
                                    CloudTrail trail of its own - a customer-managed-key requirement cannot be met

orders
  MEDIUM  gsi-idle                  GSI by-status consumed 0.000 capacity units on average over 14d - it is paid for on every
                                    write and read by nobody
  MEDIUM  gsi-projects-all          GSI by-customer projects ALL, so every write to the 8.0 GiB base table is replicated in
                                    full into the index (6.0 GiB); switch to KEYS_ONLY or INCLUDE with the attributes the
                                    query actually reads
  LOW     no-autoscaling            provisioned mode with no Application Auto Scaling target for ReadCapacityUnits,
                                    WriteCapacityUnits - capacity only ever changes when a human notices
  HIGH    no-deletion-protection    deletion protection is off on a table holding 2,412,880 items
  HIGH    no-pitr                   point-in-time recovery is not enabled, so there is no restore window - this cannot be
                                    switched on retroactively
  LOW     no-ttl                    TTL is disabled on a table of 8.0 GiB taking 30.0 WCU of sustained writes; growth is
                                    inferred, pass --compare-json <older dump> for a measured delta
  MEDIUM  overprovisioned-capacity  500 RCU provisioned against a 40.0 consumed average (12.5x) - about $43.65/month of unused
                                    capacity
  LOW     untagged                  missing required tag(s) environment - the cost allocation report cannot attribute this
                                    table's spend

sessions
  LOW     ondemand-steady-traffic   on-demand traffic is flat (cv 0.04) and costs about $98.55/month; 125 RCU / 50 WCU
                                    provisioned with 20% headroom would cost about $35.59/month

Estimated monthly waste: $676.02
```

## How it works

Collection and judgement are separate. `collect.py` is the only module that imports boto3; it
describes every table, pulls `ConsumedReadCapacityUnits` and `ConsumedWriteCapacityUnits` from
CloudWatch for the table and each GSI, and returns one plain dict. `rules.py` consumes that
dict and nothing else.

That split is why `--dump-json` and `--from-json` exist, and why the test suite is JSON
fixtures with no AWS account anywhere — the CI job has no credentials and still exercises
every rule. It also means you can audit an account you only have a dump from.

One detail worth knowing: CloudWatch reports consumed capacity as a `Sum` over the period, and
a provisioned capacity number is denominated in units per second. The collector divides by the
period length before the rules ever see it, so comparing 500 RCU against a consumed average is
comparing the same unit.

### Exit codes

| code | meaning |
| --- | --- |
| 0 | no `--fail-on` rule fired |
| 1 | a `--fail-on` rule fired |
| 2 | bad usage, unknown rule name, or collection failed |

So in CI:

```shell
aws-dynamodb-audit --region eu-central-1 --fail-on no-pitr,no-deletion-protection,aws-owned-key
```

## Pricing

Dollar figures use the published us-east-1 Standard-table list prices — $0.00013 per RCU-hour,
$0.00065 per WCU-hour, $0.125 per million read request units, $0.625 per million write request
units, over a 730-hour month. Every other region is more expensive, so the numbers are a floor
rather than a quote. Override them with `--price-rcu-hour`, `--price-wcu-hour`,
`--price-read-request` and `--price-write-request`; the values actually used are echoed in the
JSON output under `pricing`.

## Gotchas

`no-pitr` stays quiet when `DescribeContinuousBackups` returned nothing at all. An
`AccessDenied` must not read as "PITR is off" — a missing answer is not a finding.

`no-ttl` reports whether the growth was measured. With `--compare-json <older dump>` it
compares item counts between two dumps and gives you a real percentage; without one it infers
growth from sustained writes on a table over 1 GiB and says so in the message. DynamoDB does
not publish item count to CloudWatch, so there is no way to get the history from a single run.

A GSI with no CloudWatch datapoints is treated as idle, which is correct — but a GSI created
yesterday has no datapoints either. Use `--ignore-rule gsi-idle` for the first lookback window
after a change.

## Development

```shell
python3.12 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
```

## License

MIT
