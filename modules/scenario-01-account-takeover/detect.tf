locals {
  metric_namespace = "${var.name_prefix}/scenario-01"
}

# ---------------------------------------------------------------------------
# Metric-filter alarms over the CloudTrail log group. These are the
# deterministic tripwires: they fire off the attack's OWN signal, no GuardDuty
# baseline required.
#
# The two non-obvious settings that make an alarm actually fire:
#   - default_value = 0  -> the metric always has data, so the alarm can leave
#                           INSUFFICIENT_DATA and transition to ALARM.
#   - treat_missing_data = notBreaching on the alarm, Sum over a 5-min period.
# ---------------------------------------------------------------------------

# Enumeration: a burst of AccessDenied / UnauthorizedOperation.
resource "aws_cloudwatch_log_metric_filter" "access_denied" {
  name           = "${var.name_prefix}-access-denied"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{ ($.errorCode = \"AccessDenied\") || ($.errorCode = \"*UnauthorizedOperation\") }"

  metric_transformation {
    name          = "AccessDeniedCount"
    namespace     = local.metric_namespace
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "access_denied" {
  alarm_name          = "${var.name_prefix}-enumeration-burst"
  alarm_description   = "A burst of AccessDenied calls - looks like a principal enumerating what a key can do."
  namespace           = local.metric_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.access_denied.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.sns_topic_arn]
  ok_actions          = [var.sns_topic_arn]
}

# Persistence / escalation: new users, keys, policy attachments, trust edits.
resource "aws_cloudwatch_log_metric_filter" "iam_persistence" {
  name           = "${var.name_prefix}-iam-persistence"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{ ($.eventName = \"CreateUser\") || ($.eventName = \"CreateAccessKey\") || ($.eventName = \"AttachUserPolicy\") || ($.eventName = \"AttachRolePolicy\") || ($.eventName = \"PutUserPolicy\") || ($.eventName = \"UpdateAssumeRolePolicy\") }"

  metric_transformation {
    name          = "IamPersistenceCount"
    namespace     = local.metric_namespace
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_persistence" {
  alarm_name          = "${var.name_prefix}-iam-persistence"
  alarm_description   = "IAM create/attach/trust-edit calls - the shape of an attacker planting persistence."
  namespace           = local.metric_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.iam_persistence.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.sns_topic_arn]
  ok_actions          = [var.sns_topic_arn]
}

# ---------------------------------------------------------------------------
# GuardDuty findings -> EventBridge -> SNS (notify) + quarantine Lambda (respond).
# The quarantine target lives in respond.tf.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.name_prefix}-guardduty-findings"
  description = "Route GuardDuty findings to alerting and automated quarantine."
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty_to_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "notify-sns"
  arn       = var.sns_topic_arn
}
