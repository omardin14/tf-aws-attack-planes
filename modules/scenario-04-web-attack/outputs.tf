output "alb_dns_name" {
  description = "Public DNS name of the target ALB - the endpoint the attack hits."
  value       = aws_lb.this.dns_name
}

output "alb_arn" {
  description = "ARN of the target ALB."
  value       = aws_lb.this.arn
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF web ACL associated with the ALB."
  value       = aws_wafv2_web_acl.this.arn
}

output "attack_function_name" {
  description = "Invoke this manually (auto_fire=false, or via simulate-attack.sh -s 4) to re-run the attack."
  value       = aws_lambda_function.attack.function_name
}

output "alb_access_logs_table" {
  description = "Glue table of ALB access logs to query in Athena."
  value       = "${var.glue_database_name}.${aws_glue_catalog_table.alb_access_logs.name}"
}

output "waf_log_group_name" {
  description = "CloudWatch Logs group the WAF logs deliver to (where the blocked-requests alarm watches, and the saved Logs Insights query reads)."
  value       = aws_cloudwatch_log_group.waf.name
}

output "alarm_names" {
  description = "The metric-filter alarm that trips on a burst of WAF-blocked requests."
  value       = [aws_cloudwatch_metric_alarm.waf_blocks.alarm_name]
}
