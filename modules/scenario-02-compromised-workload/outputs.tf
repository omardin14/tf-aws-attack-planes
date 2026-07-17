output "instance_id" {
  description = "The compromised workload EC2 instance - the box you investigate."
  value       = aws_instance.workload.id
}

output "instance_security_group_id" {
  description = "The instance's baseline security group. simulate-attack.sh restores this before each re-run to undo any isolation."
  value       = aws_security_group.workload.id
}

output "attack_function_name" {
  description = "Invoke this manually (auto_fire=false, or via simulate-attack.sh -s 2) to re-run the attack."
  value       = aws_lambda_function.attack.function_name
}

output "flow_log_group_name" {
  description = "CloudWatch Logs group the VPC Flow Logs deliver to (where the egress metric-filter alarm watches)."
  value       = aws_cloudwatch_log_group.flow_logs.name
}

output "flow_logs_s3_path" {
  description = "S3 prefix the VPC Flow Logs are written to (queried by the Glue table via partition projection)."
  value       = local.flow_logs_location
}

output "flow_logs_table" {
  description = "Glue table to query in Athena."
  value       = "${var.glue_database_name}.${aws_glue_catalog_table.flow_logs.name}"
}

output "alarm_names" {
  description = "The metric-filter alarm that trips on the exfil."
  value       = [aws_cloudwatch_metric_alarm.egress_exfil.alarm_name]
}
