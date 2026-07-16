"""Automated response: isolate the compromised instance.

Triggered by EventBridge on a GuardDuty finding. Isolates by swapping the
instance's security groups to a no-rules "isolation" SG (env ISOLATION_SG_ID) -
cutting all ingress and egress, so an in-progress exfil stops and a human has
time to catch up. This is the network-plane analogue of scenario 1's quarantine
(which attaches AWSDenyAll to the compromised user).

The swap is deliberately out-of-band: Terraform ignore_changes the instance's
SGs, so this doesn't fight state. simulate-attack.sh restores the baseline SG
before each re-run (the reset), mirroring scenario 1's un-quarantine step.

GuardDuty *sample* findings carry a placeholder resource, not your real instance
id - so on a sample finding we fall back to the configured instance id from env.
Real findings are trusted as parsed.
"""

import os

import boto3
from botocore.exceptions import ClientError


def resolve_instance(event):
    detail = event.get("detail", {})
    is_sample = (
        detail.get("service", {}).get("additionalInfo", {}).get("sample", False)
    )
    parsed = (
        detail.get("resource", {})
        .get("instanceDetails", {})
        .get("instanceId", "")
    )

    if is_sample or not parsed or parsed.startswith("i-99999999"):
        instance_id = os.environ["INSTANCE_ID"]
        print(f"[i] sample/placeholder finding -> isolating configured instance {instance_id}")
    else:
        instance_id = parsed
        print(f"[i] real finding -> isolating {instance_id}")
    return instance_id, is_sample


def handler(event, context):
    instance_id, is_sample = resolve_instance(event)
    isolation_sg = os.environ["ISOLATION_SG_ID"]

    ec2 = boto3.client("ec2")
    try:
        ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[isolation_sg])
        print(f"[+] swapped {instance_id} into isolation SG {isolation_sg}")
    except ClientError as exc:
        print(f"[-] isolation failed ({exc.response['Error']['Code']})")
        raise

    return {"isolated": instance_id, "isolation_sg": isolation_sg, "sample": is_sample}
