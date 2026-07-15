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
└── scripts/
    └── simulate-attack.sh   # fire the attack Lambda on demand, N times (see "Re-run the attack")
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

> [!NOTE]
> **Email alerts and the "Deleted" subscription.** AWS requires you to confirm an email
> subscription by clicking the link it sends — Terraform can't do this for you. Two things
> follow from that:
> - After each `apply` you must click the confirmation link. `apply` now waits up to 10
>   minutes for you (see `confirmation_timeout_in_minutes`) and returns as soon as you click.
>   If you miss the window the subscription still works once confirmed, but Terraform state
>   shows `pending_confirmation = true`.
> - Every `terraform destroy` unsubscribes the email. If you're iterating with
>   destroy/re-apply, the SNS console shows the torn-down subscription as a `Deleted` row
>   (a temporary tombstone, keeping its last "Confirmed" status) and the next `apply` creates
>   a fresh one to re-confirm. That churn is expected, not the scenario deleting anything —
>   nothing in the attack/response code touches SNS. Leave `alert_email = ""` while iterating
>   (alarms are still visible in the CloudWatch console) and set it only for a run you keep.

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

Use the helper script to fire the attack Lambda on demand — as many times as you like — so
you can regenerate the signal without re-applying:

```bash
./scripts/simulate-attack.sh              # fire once
./scripts/simulate-attack.sh -n 5 -i 30   # fire 5 times, 30s apart
./scripts/simulate-attack.sh --help       # all options
```

It discovers the function name and region from `terraform output`, so a bare run works from a
checkout with live state. You can also point it anywhere with `--function-name`/`--name-prefix`
and `--region`. Set `-var 'auto_fire=false'` on apply to stand up the estate without firing,
then drive it entirely from the script.

Under the hood it's just:
`aws lambda invoke --function-name "$(terraform output -raw attack_function_name)" /dev/null`

### Exercise GuardDuty directly

Requires `enable_guardduty = true` (otherwise `guardduty_detector_id` is empty and there's
no detector to sample against).

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
| `alert_email` | `""` | Subscribe an email to the SNS alert topic. You must confirm it via the emailed link (see the email-alerts note under Usage). |
| `auto_fire` | `true` | Fire the attack on apply. Set `false` to fire it manually later. |
| `enable_guardduty` | `false` | Stand up the GuardDuty detector + its EventBridge→SNS/quarantine wiring. Off by default because **GuardDuty is not on the AWS Free Tier**. See the note below. |

> [!NOTE]
> **GuardDuty and the Free Tier.** GuardDuty is a paid service, so `enable_guardduty`
> defaults to `false` and the demo runs Free-Tier-friendly out of the box. With it off you
> still get the whole **trigger → detect → investigate** loop: the CloudTrail metric-filter
> alarms fire off the attack's own signal, and all the Athena queries work. What you lose is
> the GuardDuty-driven **auto-quarantine** — the detector, its EventBridge rule, and the
> sample-finding step are skipped. The quarantine Lambda is still created, so you can invoke
> it by hand to demo the response step. Set `enable_guardduty = true` on a sandbox account
> where you're happy to pay for GuardDuty to exercise the full detect→respond pipeline.
