# tf-aws-attack-planes
#
# Companion Terraform for the "every attack lives in a different plane" blog series.
# This root wires the shared `foundation` (the audit-logging estate every scenario
# reuses) to `scenario-01-account-takeover` (the leaked-key control-plane attack).
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

module "scenario_01" {
  source = "./modules/scenario-01-account-takeover"

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
