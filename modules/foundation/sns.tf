# Shared alert topic. Metric alarms and GuardDuty EventBridge rules publish here.

resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email

  # Email subscriptions can't be confirmed by Terraform - you click the link in
  # the email. The default wait is 1 minute, which is easy to miss, leaving state
  # stuck at pending_confirmation=true (the subscription still works once you
  # confirm, but Terraform thinks it's pending). Give yourself 10 minutes to
  # click. Terraform returns as soon as you confirm, so this is a ceiling, not a
  # fixed delay.
  confirmation_timeout_in_minutes = 10
}

# Allow CloudWatch Alarms and EventBridge to publish to the topic.
data "aws_iam_policy_document" "alerts" {
  statement {
    sid     = "AllowServicesToPublish"
    effect  = "Allow"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts.json
}
