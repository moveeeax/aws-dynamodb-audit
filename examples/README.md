# examples

- `account-dump.json` — a four-table account captured with `--dump-json`. `orders` is the
  interesting one: provisioned at 12.5x its consumed reads, PITR off, deletion protection off,
  one GSI projecting `ALL` and another nobody queries. `archive` is 1000/1000 provisioned
  against zero traffic. `audit-log` sits on the AWS-owned key. `sessions` is on-demand with
  traffic flat enough that provisioned would be a third of the price.
- `report.txt` — the text report for that dump, produced with
  `aws-dynamodb-audit --from-json examples/account-dump.json --require-tags owner,environment`.
- `report.json` — the same run with `--format json`.

Regenerate both after changing a rule message:

```shell
aws-dynamodb-audit --from-json examples/account-dump.json --require-tags owner,environment > examples/report.txt
aws-dynamodb-audit --from-json examples/account-dump.json --format json > examples/report.json
```
