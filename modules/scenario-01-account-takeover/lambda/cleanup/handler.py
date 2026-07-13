"""Destroy-time cleanup of out-of-band persistence.

The attack Lambda creates a backdoor IAM user + access key that Terraform does
NOT manage, so `terraform destroy` would leave live credentials behind. This
Lambda is invoked by a destroy-time provisioner: it finds every user matching the
persistence prefix, strips its keys/policies, and deletes it.
"""

import os

import boto3


def _purge_user(iam, name):
    for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
        iam.delete_access_key(UserName=name, AccessKeyId=key["AccessKeyId"])
    for pol in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]:
        iam.detach_user_policy(UserName=name, PolicyArn=pol["PolicyArn"])
    for pname in iam.list_user_policies(UserName=name)["PolicyNames"]:
        iam.delete_user_policy(UserName=name, PolicyName=pname)
    iam.delete_user(UserName=name)
    print(f"[+] purged {name}")


def handler(event, context):
    prefix = os.environ["PERSIST_PREFIX"]
    iam = boto3.client("iam")
    deleted = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            if user["UserName"].startswith(prefix):
                _purge_user(iam, user["UserName"])
                deleted.append(user["UserName"])
    print(f"[+] deleted {len(deleted)} persistence users: {deleted}")
    return {"deleted": deleted}
