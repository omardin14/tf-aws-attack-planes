# The always-on tripwire. Reads CloudTrail/VPC/DNS independently of your own logs.
# Real IAMUser findings need days of behavioural baseline, so scenarios exercise the
# detect->respond pipeline deterministically via `aws guardduty create-sample-findings`.
#
# NOTE: aws_guardduty_detector fails if a detector already exists in the account/region.
# This demo assumes a clean sandbox account.
#
# GuardDuty is NOT part of the AWS Free Tier, so it is gated behind enable_guardduty
# (default false). When off, the scenario still detects the attack via CloudTrail
# metric-filter alarms; only the GuardDuty-driven auto-quarantine path is skipped.

resource "aws_guardduty_detector" "this" {
  count = var.enable_guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}
