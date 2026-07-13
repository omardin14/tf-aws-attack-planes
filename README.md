# tf-aws-attack-planes

Companion Terraform for the blog series **"every attack lives in a different plane."**
Each scenario stands up a small, deliberately-attackable slice of an AWS estate, fires a
simulated attack against it, detects the attack, and gives you the saved queries to
investigate it — so you can run the whole "what is this user doing?" loop yourself.

> [!WARNING]
> This intentionally creates an over-permissive IAM user, leaks its access key, and runs a
> simulated attack (enumeration + privilege escalation + persistence) against **your own
> account**. The attack Lambda also creates a backdoor IAM user out-of-band.
> **Apply this only in a dedicated throwaway sandbox account.** Never in production, never
> in a shared account. A permissions boundary or SCP on the sandbox is a sensible extra guard.

---

## Layout

```
.
├── modules/
│   ├── foundation/                    # shared audit-logging estate, reused by every scenario
│   │   • multi-region CloudTrail (log-file validation, global events)
│   │     delivering to BOTH S3 (forensics/Athena) and CloudWatch Logs (alarms)
│   │   • S3 log bucket · Athena workgroup + Glue database · GuardDuty · SNS alert topic
│   └── scenario-01-account-takeover/  # the leaked-key control-plane attack
│       ├── attack.tf        # (1) trigger:     leaked user + key + auto-firing attack Lambda
│       ├── detect.tf        # (2) detect:      CloudTrail metric-filter alarms + GuardDuty→EventBridge
│       ├── respond.tf       # (2) respond:     quarantine Lambda (deny-all) + destroy-time cleanup
│       └── investigate.tf   # (3) investigate: Glue table (partition projection) + saved Athena queries
```

Every scenario module follows the same three-part shape: **trigger the attack · detect it ·
investigate it.** Scenario 1 is the reference the later planes (Network / DNS / Web / Storage)
copy.

## Scenario 1 — Account Takeover (control plane / CloudTrail)

A long-lived IAM key leaks. Someone orients (`GetCallerIdentity`, `ListUsers`,
`ListAllMyBuckets`), enumerates what the key can do (a burst of `AccessDenied`), then
escalates and plants persistence (a new admin user + access key). The whole story is
CloudTrail events tagged with the same `userIdentity` — which is exactly what makes the
investigation a single query.

## Usage

```bash
terraform init
terraform apply -var 'alert_email=you@example.com'
```

On apply:
1. The foundation + scenario stand up.
2. The attack Lambda fires (signing every call with the **leaked key**, so CloudTrail
   attributes the whole chain to the leaked user), and ends by generating a GuardDuty
   **sample finding** to exercise the response pipeline.
3. The metric-filter alarms trip; the quarantine Lambda attaches `AWSDenyAll` to the user;
   SNS emails you (confirm the subscription first).

> [!NOTE]
> CloudTrail → CloudWatch Logs delivery lags **~1–2 minutes**, so the alarms go to ALARM a
> couple of minutes *after* the attack Lambda runs. That delay is expected, not a bug.

### Investigate

Open the Athena workgroup from the `athena_workgroup` output (or the `athena_console_url`
deep link) and run the saved queries, in order:

| Query | Answers |
|---|---|
| `s01-01-what-is-this-user-doing` | The full timeline for the leaked principal. |
| `s01-02-enumeration-error-rate`  | The `AccessDenied` burst — enumeration made legible. |
| `s01-03-persistence-actions`     | New users / keys / policy attaches — the persistence. |
| `s01-04-source-ips-and-agents`   | Where they called from, and with what tooling. |

### Re-run the attack

`aws lambda invoke --function-name $(terraform output -raw leaked_user_name | sed 's/-leaked-ci-user/-attack/') /dev/null`
— or set `-var 'auto_fire=false'` to stand up the estate without firing, and invoke the
attack Lambda yourself when you're ready.

### Exercise GuardDuty directly

```bash
aws guardduty create-sample-findings \
  --detector-id "$(terraform output -raw guardduty_detector_id)" \
  --finding-types UnauthorizedAccess:IAMUser/MaliciousIPCaller
```

## Teardown

```bash
terraform destroy
```

A **destroy-time provisioner** invokes a cleanup Lambda that deletes the backdoor IAM
user(s) the attack created out-of-band (Terraform can't track them). This step shells out
to the **AWS CLI** — make sure it's installed and authenticated on the machine running
`destroy`. If you ever destroy without the CLI available, run the cleanup Lambda manually
first, or delete any `atkplane-persist-*` IAM users by hand.

## Cost

Small but non-zero while running: GuardDuty, CloudTrail management events, S3 storage, a few
Lambda invocations, CloudWatch alarms. Destroy when you're done. `force_destroy` is set on
the log bucket so teardown doesn't choke on the objects CloudTrail wrote.

## Variables

| Variable | Default | Purpose |
|---|---|---|
| `region` | `us-east-1` | Home region. Keep `us-east-1` so global IAM/STS events land here. |
| `name_prefix` | `atkplane` | Prefix on every resource — makes the demo easy to find and tear down. |
| `alert_email` | `""` | Subscribe an email to the SNS alert topic (confirm the subscription). |
| `auto_fire` | `true` | Fire the attack on apply. Set `false` to fire it manually later. |
