# ---------------------------------------------------------------------------
# The attacker. Unlike the earlier planes there is no box to drive - the web
# plane's traffic arrives over HTTP from the internet, so the attack Lambda just
# makes outbound requests to the ALB's public URL. It fires the three signatures
# from the theory: SQLi-shaped query strings (tripping the SQLi managed rule ->
# BLOCK), a burst of requests (tripping the rate rule), and a spray of 404-path
# scanning.
#
# Honest note: because the requests originate from a Lambda, the "attacker IP" in
# your logs is the Lambda's egress address, not a spoofed internet IP - fine for
# seeing exactly how the logs and rules behave. The Lambda is deliberately NOT in
# the VPC, so it has ordinary internet egress and reaches the ALB's public DNS
# name; it needs no AWS permissions beyond basic execution (it calls no AWS API).
# ---------------------------------------------------------------------------
data "archive_file" "attack" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/attack"
  output_path = "${path.module}/build/attack.zip"
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "attack" {
  name               = "${var.name_prefix}-s4-attack-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Basic execution is all it needs - the attack is plain outbound HTTP, no AWS API.
resource "aws_iam_role_policy_attachment" "attack_basic" {
  role       = aws_iam_role.attack.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "attack" {
  function_name    = "${var.name_prefix}-s4-attack"
  filename         = data.archive_file.attack.output_path
  source_code_hash = data.archive_file.attack.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.attack.arn
  timeout          = 300

  environment {
    variables = {
      ALB_URL     = "http://${aws_lb.this.dns_name}"
      SQLI_COUNT  = tostring(var.sqli_count)
      SCAN_COUNT  = tostring(var.scan_count)
      BURST_COUNT = tostring(var.burst_count)
      SCAN_PATHS  = var.scan_paths
    }
  }
}

# An ALB takes a couple of minutes to become active and for its DNS name to
# resolve; WAF association + logging must also be live so the first requests are
# actually evaluated and logged. Gate the auto-fire behind a sleep (the handler
# ALSO retries DNS resolution internally). Same shape as the SSM-registration
# sleeps in the earlier scenarios.
resource "time_sleep" "alb_ready" {
  depends_on = [
    aws_lb_listener.http,
    aws_lb_listener_rule.root,
    aws_wafv2_web_acl_association.this,
    aws_wafv2_web_acl_logging_configuration.this,
  ]
  create_duration = "180s"
}

# Auto-fire on apply. Static input so a plain re-apply never re-fires the
# side-effecting attack. depends_on the detection stack so the tripwire is live
# BEFORE the attack generates its blocked-request signal.
resource "aws_lambda_invocation" "attack" {
  count = var.auto_fire ? 1 : 0

  function_name = aws_lambda_function.attack.function_name
  input         = jsonencode({ trigger = "terraform-apply" })

  depends_on = [
    time_sleep.alb_ready,
    aws_cloudwatch_log_metric_filter.waf_blocks,
    aws_cloudwatch_metric_alarm.waf_blocks,
    aws_wafv2_web_acl_logging_configuration.this,
  ]
}
