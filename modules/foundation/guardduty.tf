# The always-on tripwire. Reads CloudTrail/VPC/DNS independently of your own logs.
# Real IAMUser findings need days of behavioural baseline, so scenarios exercise the
# detect->respond pipeline deterministically via `aws guardduty create-sample-findings`.
#
# NOTE: aws_guardduty_detector fails if a detector already exists in the account/region.
# This demo assumes a clean sandbox account.

resource "aws_guardduty_detector" "this" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}
