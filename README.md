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
│   ├── scenario-01-account-takeover/  # the leaked-key control-plane attack
│   │   ├── attack.tf        # (1) trigger:     leaked user + key + auto-firing attack Lambda
│   │   ├── detect.tf        # (2) detect:      CloudTrail metric-filter alarms + GuardDuty→EventBridge
│   │   ├── respond.tf       # (2) respond:     quarantine Lambda (deny-all) + destroy-time cleanup
│   │   └── investigate.tf   # (3) investigate: Glue table (partition projection) + saved Athena queries
│   └── scenario-02-compromised-workload/  # the network-plane egress/lateral-movement attack
│       ├── network.tf       # (0) target:      VPC + public subnet + IMDSv2 EC2 + VPC Flow Logs (→ S3 + CWL)
│       ├── attack.tf        # (1) trigger:     attack Lambda drives the box via SSM (exfil + REJECT probes)
│       ├── detect.tf        # (2) detect:      egress-bytes metric-filter alarm + GuardDuty→EventBridge
│       ├── respond.tf       # (2) respond:     isolation Lambda (swap to a no-rules SG)
│       └── investigate.tf   # (3) investigate: Glue table over Flow Logs + saved Athena queries
└── scripts/
    └── simulate-attack.sh   # fire a scenario's attack Lambda on demand, N times (see "Re-run the attack")
```

Every scenario module follows the same shape: **trigger the attack · detect it · investigate
it** (with an optional **respond** step). Scenario 1 is the reference the later planes (Network
/ DNS / Web / Storage) copy.

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

> [!NOTE]
> **Why a plain re-invoke fails, and how the script fixes it.** The respond pipeline quarantines
> the leaked user by attaching `AWSDenyAll` to it — so the *first* run succeeds, but the leaked
> key that signs the attack is then denied everything, and every later run gets `AccessDenied`.
> The script clears that quarantine (detaches `AWSDenyAll` from the leaked user) before each run,
> which is what makes the scenario repeatable; this needs `iam:DetachUserPolicy` on your caller.
> Pass `--no-reset` to leave the quarantine in place and observe the denied state instead.

Under the hood each run is just: clear the quarantine, then
`aws lambda invoke --function-name "$(terraform output -raw attack_function_name)" /dev/null`

### Exercise GuardDuty directly

Requires `enable_guardduty = true` (otherwise `guardduty_detector_id` is empty and there's
no detector to sample against).

```bash
aws guardduty create-sample-findings \
  --detector-id "$(terraform output -raw guardduty_detector_id)" \
  --finding-types UnauthorizedAccess:IAMUser/MaliciousIPCaller
```

## Scenario 2 — Compromised Workload (network plane / VPC Flow Logs)

A workload is handed a static, over-permissive credential. The box is compromised, an attacker
lands on it, and does two things CloudTrail can't see: **exfiltrates data** to the outside, and
**probes east-west** for what else it can reach. Neither is an AWS API call — they only exist as
traffic on the instance's ENI, which is exactly what **VPC Flow Logs** capture.

This scenario is **off by default** (it stands up a VPC + a `t3.micro`, a small ongoing cost).
Turn it on:

```hcl
# terraform.tfvars
scenario_02_enabled = true
auto_fire           = true
enable_guardduty    = false   # the default; true only on a paid sandbox
```

On apply the module stands up a VPC with a public subnet and one EC2 instance carrying an
over-permissive instance role (**IMDSv2 enforced** — the right default, and the point: it raises
the bar for *stealing* the creds but does nothing once an attacker has code execution). VPC Flow
Logs with a custom format deliver to **both** a dedicated CloudWatch group (the alarm) and the
shared S3 bucket (Athena). The attack Lambda then drives the box via `ssm:SendCommand`: it reads
the instance creds from IMDS, POSTs a few MB of **egress** to an external endpoint, and fans out
**REJECT** probes to neighbours. The `atkplane-egress-exfil` alarm trips and SNS emails you.

> [!NOTE]
> VPC Flow Logs are set to `max_aggregation_interval = 60`, but delivery still lags the attack
> by a minute or two — same shape as CloudTrail's delivery lag. The alarm going ALARM a couple
> of minutes *after* the attack is expected, not a bug.

### Investigate — the first cross-plane story

CloudTrail can show the instance role making calls it's never made, but it can't tell you *where
the data went* — egress isn't an API call. For that you need Flow Logs. Open the Athena workgroup
and run the saved queries:

| Query | Answers |
|---|---|
| `s02-01-top-talkers-egress-bytes` | Top talkers to the outside world — a single destination dominating the bytes column is the exfil. |
| `s02-02-reject-lateral-movement-probe` | The lateral-movement probe — refused connections fanned across internal addresses/ports. |
| `s02-03-compromised-instance-egress-timeline` | Egress from the compromised instance over time — line it up with the alarm. |

### Re-run the attack

Same helper script, pointed at scenario 2 with `-s 2`:

```bash
./scripts/simulate-attack.sh -s 2                 # fire once
./scripts/simulate-attack.sh -s 2 -n 5 -i 60      # fire 5 times, 60s apart
```

Recommend `-i 60` or more so each egress spike (aggregation interval + delivery lag) surfaces as
a distinct alarm transition. When GuardDuty is on, the respond pipeline isolates the box by
swapping it into a no-rules SG; the script restores the instance's **baseline security group**
before each run (undo the isolation), exactly as the scenario-1 path clears the `AWSDenyAll`
quarantine. Pass `--no-reset` to leave it isolated and observe the cut-off state. The scenario-2
reset needs `ec2:ModifyInstanceAttribute` + `ec2:DescribeInstances` on your caller.

> [!NOTE]
> **The finding to know by heart:** `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`.
> It fires when credentials issued to an EC2 instance role are used from an IP *outside* AWS. With
> `enable_guardduty = true` the attack emits a sample of it to drive the isolation Lambda; there is
> essentially no legitimate reason for your instance's role to be driving the AWS API from
> someone's laptop.

## Teardown

```bash
terraform destroy
```

> [!NOTE]
> **Scenario 2 tears down a VPC**, and VPCs are fussy to delete while anything is still attached.
> Terraform orders it correctly (Flow Logs, the ENI, and the instance go before the VPC), but if a
> destroy ever hangs on the VPC, a lingering ENI is almost always the culprit. The attack itself
> creates no out-of-band AWS resources (only network traffic + an IMDS read), so — unlike
> scenario 1 — there is no cleanup Lambda to run.

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
| `scenario_01_enabled` | `true` | Deploy Scenario 1 (account takeover / control plane). Cheap — no compute — so on by default. |
| `scenario_02_enabled` | `false` | Deploy Scenario 2 (compromised workload / network plane). Off by default because it stands up a VPC + a `t3.micro` EC2 instance (small ongoing cost). |

> [!NOTE]
> **GuardDuty and the Free Tier.** GuardDuty is a paid service, so `enable_guardduty`
> defaults to `false` and the demo runs Free-Tier-friendly out of the box. With it off you
> still get the whole **trigger → detect → investigate** loop: the CloudTrail metric-filter
> alarms fire off the attack's own signal, and all the Athena queries work. What you lose is
> the GuardDuty-driven **auto-quarantine** — the detector, its EventBridge rule, and the
> sample-finding step are skipped. The quarantine Lambda is still created, so you can invoke
> it by hand to demo the response step. Set `enable_guardduty = true` on a sandbox account
> where you're happy to pay for GuardDuty to exercise the full detect→respond pipeline.
