output "instance_id" {
  description = "The DNS-noisy EC2 instance - the box you investigate."
  value       = aws_instance.workload.id
}

output "attack_function_name" {
  description = "Invoke this manually (auto_fire=false, or via simulate-attack.sh -s 3) to re-run the attack."
  value       = aws_lambda_function.attack.function_name
}

output "hunter_function_name" {
  description = "The scheduled DNS hunter Lambda. Invoke it by hand to run the beacon/tunnelling hunt immediately instead of waiting for its next scheduled pass."
  value       = aws_lambda_function.hunt.function_name
}

output "hunter_schedule_rule_name" {
  description = "EventBridge rule that runs the hunter every few minutes."
  value       = aws_cloudwatch_event_rule.hunter_schedule.name
}

output "resolver_query_logs_table" {
  description = "Glue table of Route 53 Resolver query logs to query in Athena."
  value       = "${var.glue_database_name}.${aws_glue_catalog_table.resolver_logs.name}"
}

output "resolver_query_logs_s3_path" {
  description = "S3 prefix the Resolver query logs are written to (queried by the Glue table via partition projection)."
  value       = local.resolver_logs_location
}

output "dns_firewall_rule_group_id" {
  description = "The DNS Firewall rule group (the 'prevent' control). null unless enable_dns_firewall = true."
  value       = one(aws_route53_resolver_firewall_rule_group.this[*].id)
}
