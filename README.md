# aws-dynamodb-audit
Static audit of DynamoDB tables: PITR off, no deletion protection, AWS-owned keys, overprovisioned capacity, GSIs projecting ALL, missing TTL. Reads live tables via boto3 or a JSON dump, so every rule is testable offline.
