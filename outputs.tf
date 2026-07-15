output "log_bucket" {
  description = "S3 bucket holding CloudTrail logs (and Athena results under athena-results/)."
  value       = module.foundation.log_bucket_id
}

output "cloudtrail_log_group" {
  description = "CloudWatch Logs group the trail delivers to (where the metric-filter alarms watch)."
  value       = module.foundation.cloudtrail_log_group_name
}

output "athena_workgroup" {
  description = "Open this workgroup in the Athena console to run the saved investigation queries."
  value       = module.foundation.athena_workgroup_name
}

output "glue_database" {
  description = "Glue database containing the cloudtrail_logs table."
  value       = module.foundation.glue_database_name
}

output "guardduty_detector_id" {
  description = "Feed this to `aws guardduty create-sample-findings` to exercise the detect->respond pipeline."
  value       = module.foundation.guardduty_detector_id
}

output "leaked_user_name" {
  description = "The deliberately-leaked IAM user. This is the principal you investigate."
  value       = module.scenario_01.leaked_user_name
}

output "attack_function_name" {
  description = "The attack Lambda. Invoke it (e.g. via scripts/simulate-attack.sh) to re-run the scenario on demand."
  value       = module.scenario_01.attack_function_name
}

output "region" {
  description = "Region the estate is deployed in (where you invoke the attack Lambda)."
  value       = var.region
}

output "athena_console_url" {
  description = "Deep link to the Athena query editor for this workgroup."
  value       = "https://${var.region}.console.aws.amazon.com/athena/home?region=${var.region}#/query-editor"
}
