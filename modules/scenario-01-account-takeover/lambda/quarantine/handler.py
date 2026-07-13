"""Automated response: quarantine the compromised principal.

Triggered by EventBridge on a GuardDuty finding. Quarantines by ATTACHING the
AWS-managed AWSDenyAll policy to the user (rather than deactivating the key,
which would fight Terraform for ownership of the key's status). The attachment is
something Terraform doesn't own, so it's cleanly reversible.

GuardDuty *sample* findings carry a placeholder identity (GeneratedFindingUserName),
not your real user - so on a sample finding we fall back to the leaked username
passed in via env. Real findings are trusted as parsed.
"""

import os

import boto3
from botocore.exceptions import ClientError

DENY_ALL = "arn:aws:iam::aws:policy/AWSDenyAll"


def handler(event, context):
    detail = event.get("detail", {})
    is_sample = (
        detail.get("service", {}).get("additionalInfo", {}).get("sample", False)
    )
    parsed = (
        detail.get("resource", {}).get("accessKeyDetails", {}).get("userName", "")
    )

    if is_sample or not parsed or parsed.startswith("GeneratedFinding"):
        username = os.environ["LEAKED_USERNAME"]
        print(f"[i] sample/placeholder finding -> quarantining configured user {username}")
    else:
        username = parsed
        print(f"[i] real finding -> quarantining {username}")

    iam = boto3.client("iam")
    try:
        iam.attach_user_policy(UserName=username, PolicyArn=DENY_ALL)
        print(f"[+] attached AWSDenyAll to {username}")
    except ClientError as exc:
        print(f"[-] quarantine failed ({exc.response['Error']['Code']})")
        raise

    return {"quarantined": username, "sample": is_sample}
