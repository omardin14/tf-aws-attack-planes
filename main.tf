# tf-aws-attack-planes
#
# Companion Terraform for the "every attack lives in a different plane" blog series.
# This root wires the shared `foundation` (the audit-logging estate every scenario
# reuses) to the per-plane scenarios: `scenario-01-account-takeover` (leaked-key
# control-plane attack) and `scenario-02-compromised-workload` (network-plane
# egress/lateral-movement caught in VPC Flow Logs). Each scenario is gated by its
# own `scenario_NN_enabled` flag.
#
# WARNING: This intentionally stands up a deliberately-vulnerable IAM user and fires
# a simulated attack against your own account. Apply it ONLY in a dedicated sandbox
# account you are happy to destroy. See README.md.

module "foundation" {
  source = "./modules/foundation"

  name_prefix      = var.name_prefix
  alert_email      = var.alert_email
  enable_guardduty = var.enable_guardduty
}

# scenario_01 gained a `count` (the scenario_NN_enabled toggle), which shifts its
# resources from module.scenario_01.* to module.scenario_01[0].*. Migrate existing
# state in place so the toggle doesn't destroy/recreate an already-applied estate.
moved {
  from = module.scenario_01
  to   = module.scenario_01[0]
}

module "scenario_01" {
  source = "./modules/scenario-01-account-takeover"
  count  = var.scenario_01_enabled ? 1 : 0

  name_prefix      = var.name_prefix
  auto_fire        = var.auto_fire
  enable_guardduty = var.enable_guardduty

  # Wiring from the shared foundation.
  account_id                = module.foundation.account_id
  region                    = var.region
  cloudtrail_log_group_arn  = module.foundation.cloudtrail_log_group_arn
  cloudtrail_log_group_name = module.foundation.cloudtrail_log_group_name
  log_bucket_id             = module.foundation.log_bucket_id
  glue_database_name        = module.foundation.glue_database_name
  athena_workgroup_name     = module.foundation.athena_workgroup_name
  sns_topic_arn             = module.foundation.sns_topic_arn
  guardduty_detector_id     = module.foundation.guardduty_detector_id
}

module "scenario_02" {
  source = "./modules/scenario-02-compromised-workload"
  count  = var.scenario_02_enabled ? 1 : 0

  name_prefix      = var.name_prefix
  auto_fire        = var.auto_fire
  enable_guardduty = var.enable_guardduty

  # Wiring from the shared foundation. Scenario 2 delivers VPC Flow Logs to the
  # shared bucket (needs its ARN) and stands up its own flow-log CloudWatch group,
  # so it does NOT consume the CloudTrail log group scenario 1 watches.
  account_id            = module.foundation.account_id
  region                = var.region
  log_bucket_id         = module.foundation.log_bucket_id
  log_bucket_arn        = module.foundation.log_bucket_arn
  glue_database_name    = module.foundation.glue_database_name
  athena_workgroup_name = module.foundation.athena_workgroup_name
  sns_topic_arn         = module.foundation.sns_topic_arn
  guardduty_detector_id = module.foundation.guardduty_detector_id
}
