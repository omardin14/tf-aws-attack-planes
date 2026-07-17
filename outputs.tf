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
  description = "Scenario 1: the deliberately-leaked IAM user. This is the principal you investigate. null when scenario_01_enabled = false."
  value       = one(module.scenario_01[*].leaked_user_name)
}

output "attack_function_name" {
  description = "Scenario 1 attack Lambda. Invoke it (e.g. via scripts/simulate-attack.sh) to re-run the scenario on demand. null when scenario_01_enabled = false."
  value       = one(module.scenario_01[*].attack_function_name)
}

# --- Scenario 2 (compromised workload / network plane) -----------------------

output "scenario_02_instance_id" {
  description = "Scenario 2: the compromised EC2 instance. null when scenario_02_enabled = false."
  value       = one(module.scenario_02[*].instance_id)
}

output "scenario_02_instance_sg_id" {
  description = "Scenario 2: the instance's baseline security group. simulate-attack.sh restores this before each re-run to undo any isolation."
  value       = one(module.scenario_02[*].instance_security_group_id)
}

output "scenario_02_attack_function_name" {
  description = "Scenario 2 attack Lambda. Invoke it (e.g. via scripts/simulate-attack.sh -s 2) to re-run the scenario on demand."
  value       = one(module.scenario_02[*].attack_function_name)
}

output "scenario_02_flow_logs_table" {
  description = "Scenario 2: Glue table of VPC Flow Logs to query in Athena."
  value       = one(module.scenario_02[*].flow_logs_table)
}

output "scenario_02_alarm_names" {
  description = "Scenario 2: the egress metric-filter alarm that trips on exfiltration."
  value       = one(module.scenario_02[*].alarm_names)
}

output "region" {
  description = "Region the estate is deployed in (where you invoke the attack Lambda)."
  value       = var.region
}

output "athena_console_url" {
  description = "Deep link to the Athena query editor for this workgroup."
  value       = "https://${var.region}.console.aws.amazon.com/athena/home?region=${var.region}#/query-editor"
}
