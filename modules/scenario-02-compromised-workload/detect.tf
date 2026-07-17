locals {
  metric_namespace = "${var.name_prefix}/scenario-02"
}

# ---------------------------------------------------------------------------
# The tripwire: a metric filter over the Flow Logs CloudWatch group that SUMS
# egress bytes and alarms when they cross a threshold. In the demo the box is
# otherwise silent, so the exfil upload is an unambiguous spike; in production
# you'd tune this (anomaly detection) or lean on GuardDuty.
#
# Same alarm-firing tricks as scenario 1:
#   - default_value = 0  -> the metric always has data, so the alarm can leave
#                           INSUFFICIENT_DATA and transition to ALARM.
#   - treat_missing_data = notBreaching, Sum over a 5-min period.
# ---------------------------------------------------------------------------

# Positional pattern over the space-delimited custom-format flow logs. The
# bracket list MUST name all 18 fields in the SAME order as local.flow_log_format
# / local.flow_log_columns, or nothing matches (CloudWatch does not error on a
# miscount, it silently matches zero). It pins action=ACCEPT (pos 13) and
# flow_direction=egress (pos 15), and sums the named $bytes token (pos 10).
resource "aws_cloudwatch_log_metric_filter" "egress_bytes" {
  name           = "${var.name_prefix}-egress-bytes"
  log_group_name = aws_cloudwatch_log_group.flow_logs.name

  pattern = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action=\"ACCEPT\", log_status, flow_direction=\"egress\", pkt_srcaddr, pkt_dstaddr, instance_id]"

  metric_transformation {
    name          = "EgressBytes"
    namespace     = local.metric_namespace
    value         = "$bytes" # sum the bytes of every ACCEPTed egress record
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "egress_exfil" {
  alarm_name          = "${var.name_prefix}-egress-exfil"
  alarm_description   = "Large ACCEPTed egress volume from the workload subnet - the box is talking to someone it shouldn't be (data exfiltration)."
  namespace           = local.metric_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.egress_bytes.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.egress_bytes_threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.sns_topic_arn]
  ok_actions          = [var.sns_topic_arn]
}

# ---------------------------------------------------------------------------
# GuardDuty findings -> EventBridge -> SNS (notify) + isolation Lambda (respond).
# The isolation target lives in respond.tf. GuardDuty reads VPC flow data itself,
# so with it enabled you get InstanceCredentialExfiltration findings independent
# of the metric filter above.
#
# Gated on enable_guardduty (not on the Free Tier). When off, the egress alarm is
# the whole detection story and this path lies dormant.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count = var.enable_guardduty ? 1 : 0

  name        = "${var.name_prefix}-s2-guardduty-findings"
  description = "Route GuardDuty findings to alerting and automated instance isolation."
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty_to_sns" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.guardduty_findings[0].name
  target_id = "notify-sns"
  arn       = var.sns_topic_arn
}
