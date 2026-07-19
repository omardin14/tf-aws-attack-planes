"""Scheduled DNS hunter (the detect departure for the DNS plane).

DNS abuse is a pattern over a window, not a single record, so instead of a
metric-filter alarm this Lambda runs on an EventBridge schedule and hunts the
last window of Route 53 Resolver query logs in Athena for two signatures:

  * TUNNELLING - abnormally long first labels on TXT/NULL records. Normal DNS
    labels are short and boring; a long, high-entropy first label pointed at one
    domain is a file transfer wearing a DNS costume.
  * BEACON / DGA - a burst of NXDOMAIN responses concentrated on one parent
    domain: malware cycling through candidate C2 domains looking for a live one.

On a hit (either signature crosses its threshold) it publishes a summary to the
shared SNS topic. These are the same queries saved as s03-01 / s03-02 in
investigate.tf, so you can also run them by hand in Athena.
"""

import os
import time

import boto3

REGION = os.environ.get("AWS_REGION", "us-east-1")

DATABASE = os.environ["DATABASE"]
TABLE = os.environ["TABLE"]
WORKGROUP = os.environ["WORKGROUP"]
ATHENA_OUTPUT = os.environ["ATHENA_OUTPUT"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
WINDOW_MINUTES = int(os.environ.get("WINDOW_MINUTES", "15"))
TUNNEL_LABEL_LEN = int(os.environ.get("TUNNEL_LABEL_LEN", "30"))
NXDOMAIN_THRESHOLD = int(os.environ.get("NXDOMAIN_THRESHOLD", "30"))

# Only scan the last WINDOW_MINUTES of logs. Two predicates: a `date` partition
# bound so projection prunes to the last couple of days of S3 prefixes instead
# of enumerating every projected partition back to 2024 (this Lambda runs every
# few minutes), plus the precise time window on the query_timestamp string
# (ISO-8601, e.g. 2021-02-04T17:51:55Z). The 2-day slack absorbs UTC/midnight
# edges since `date` is the S3-path date, not the event time.
WINDOW_PREDICATE = (
    "\"date\" >= date_format(current_date - interval '2' day, '%Y/%m/%d') "
    "AND from_iso8601_timestamp(query_timestamp) > (now() - interval "
    f"'{WINDOW_MINUTES}' minute)"
)

TUNNELLING_SQL = f"""
SELECT query_name,
       length(split_part(query_name, '.', 1)) AS first_label_len,
       COUNT(*)                               AS lookups
FROM {TABLE}
WHERE {WINDOW_PREDICATE}
  AND query_type IN ('TXT', 'NULL')
  AND length(split_part(query_name, '.', 1)) >= {TUNNEL_LABEL_LEN}
GROUP BY query_name
ORDER BY first_label_len DESC, lookups DESC
LIMIT 20
"""

# The DGA storm surfaces as one parent domain (last two labels) with an outsized
# count of NXDOMAIN responses.
BEACON_SQL = f"""
SELECT array_join(slice(split(rtrim(query_name, '.'), '.'), -2, 2), '.') AS parent_domain,
       COUNT(*) AS nxdomain_lookups
FROM {TABLE}
WHERE {WINDOW_PREDICATE}
  AND rcode = 'NXDOMAIN'
GROUP BY array_join(slice(split(rtrim(query_name, '.'), '.'), -2, 2), '.')
HAVING COUNT(*) >= {NXDOMAIN_THRESHOLD}
ORDER BY nxdomain_lookups DESC
LIMIT 20
"""


def run_query(athena, sql):
    """Start a query, poll to completion, return its result rows as a list of
    lists of string cell values (excluding the header row)."""
    start = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": DATABASE},
        WorkGroup=WORKGROUP,
        ResultConfiguration={"OutputLocation": ATHENA_OUTPUT},
    )
    qid = start["QueryExecutionId"]

    for _ in range(40):  # ~100s ceiling, under the 120s Lambda timeout
        info = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = info["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(2.5)
    else:
        raise RuntimeError(f"query {qid} did not finish in time")

    if state != "SUCCEEDED":
        reason = info["Status"].get("StateChangeReason", "unknown")
        raise RuntimeError(f"query {qid} {state}: {reason}")

    rows = athena.get_query_results(QueryExecutionId=qid).get("ResultSet", {}).get("Rows", [])
    return [[c.get("VarCharValue", "") for c in r["Data"]] for r in rows[1:]]


def handler(event, context):
    athena = boto3.client("athena", region_name=REGION)

    tunnelling = run_query(athena, TUNNELLING_SQL)
    beacons = run_query(athena, BEACON_SQL)

    print(f"[i] window={WINDOW_MINUTES}m tunnelling_rows={len(tunnelling)} "
          f"beacon_rows={len(beacons)}")

    if not tunnelling and not beacons:
        return {"hit": False, "tunnelling": 0, "beacons": 0}

    lines = [
        "DNS hunter tripped: suspicious lookup pattern in the last "
        f"{WINDOW_MINUTES} minutes of Route 53 Resolver query logs.",
        "",
    ]
    if tunnelling:
        lines.append(f"DNS tunnelling - {len(tunnelling)} name(s) with a first label "
                     f">= {TUNNEL_LABEL_LEN} chars on TXT/NULL:")
        for name, label_len, lookups in tunnelling[:5]:
            lines.append(f"  - {name} (first label {label_len} chars, {lookups} lookups)")
        lines.append("")
    if beacons:
        lines.append(f"DGA beacon - {len(beacons)} parent domain(s) with "
                     f">= {NXDOMAIN_THRESHOLD} NXDOMAIN responses:")
        for parent, count in beacons[:5]:
            lines.append(f"  - {parent} ({count} NXDOMAIN lookups)")
        lines.append("")
    lines.append("Investigate with the s03-01 / s03-02 saved Athena queries.")

    boto3.client("sns", region_name=REGION).publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="[atkplane] DNS beacon/tunnelling detected",
        Message="\n".join(lines),
    )
    print("[+] SNS alert published")

    return {"hit": True, "tunnelling": len(tunnelling), "beacons": len(beacons)}
