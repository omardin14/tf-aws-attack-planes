locals {
  metric_namespace = "${var.name_prefix}/scenario-04"
}

# ---------------------------------------------------------------------------
# The tripwire: a metric filter over the WAF CloudWatch log group that counts
# BLOCKed requests and alarms when they cross a threshold in a 5-minute window.
#
# Note what this alarm is FOR. WAF has already blocked the traffic in real time -
# the alarm's job is not to stop the attack (the control did that) but to tell a
# human it happened. This is the web-plane version of the same alarm-firing tricks
# as scenarios 1 & 2:
#   - default_value = 0  -> the metric always has data, so the alarm can leave
#                           INSUFFICIENT_DATA and transition to ALARM.
#   - treat_missing_data = notBreaching, Sum over a 5-min period.
#
# WAF logs are JSON, so this is a JSON metric filter matching action = "BLOCK"
# (every managed-rule or rate-rule block, whatever the terminating rule).
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "waf_blocks" {
  name           = "${var.name_prefix}-waf-blocks"
  log_group_name = aws_cloudwatch_log_group.waf.name
  pattern        = "{ $.action = \"BLOCK\" }"

  metric_transformation {
    name          = "WafBlockedRequests"
    namespace     = local.metric_namespace
    value         = "1" # count blocked requests
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "waf_blocks" {
  alarm_name          = "${var.name_prefix}-waf-blocks"
  alarm_description   = "A burst of WAF-blocked requests - your rules are firing against an active attack. WAF has already stopped it; this alarm exists to tell you it happened."
  namespace           = local.metric_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.waf_blocks.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.blocked_requests_threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.sns_topic_arn]
  ok_actions          = [var.sns_topic_arn]
}

# No GuardDuty path here: GuardDuty doesn't read WAF or ALB logs, so - unlike
# scenarios 1-3 - the web plane has no GuardDuty -> EventBridge -> SNS wiring.
