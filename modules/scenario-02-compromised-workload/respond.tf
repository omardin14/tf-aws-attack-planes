# ---------------------------------------------------------------------------
# Isolation Lambda: EventBridge (GuardDuty finding) -> swap the compromised
# instance into the no-rules isolation SG (network.tf). Cuts the box off while a
# human catches up. The network-plane analogue of scenario 1's quarantine.
#
# The Lambda is ALWAYS created (so you can invoke it by hand to demo the response
# step even with GuardDuty off); only the EventBridge wiring is gated.
# ---------------------------------------------------------------------------
data "archive_file" "isolate" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/isolate"
  output_path = "${path.module}/build/isolate.zip"
}

resource "aws_iam_role" "isolate" {
  name               = "${var.name_prefix}-s2-isolate-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "isolate_basic" {
  role       = aws_iam_role.isolate.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "isolate" {
  statement {
    sid       = "IsolateInstance"
    effect    = "Allow"
    actions   = ["ec2:ModifyInstanceAttribute"]
    resources = ["arn:aws:ec2:${var.region}:${var.account_id}:instance/*"]
  }
  statement {
    sid       = "DescribeInstances"
    effect    = "Allow"
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"] # DescribeInstances does not support resource-level scoping
  }
}

resource "aws_iam_role_policy" "isolate" {
  name   = "isolate-instance"
  role   = aws_iam_role.isolate.id
  policy = data.aws_iam_policy_document.isolate.json
}

resource "aws_lambda_function" "isolate" {
  function_name    = "${var.name_prefix}-s2-isolate"
  filename         = data.archive_file.isolate.output_path
  source_code_hash = data.archive_file.isolate.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.isolate.arn
  timeout          = 30

  environment {
    variables = {
      INSTANCE_ID     = aws_instance.workload.id
      ISOLATION_SG_ID = aws_security_group.isolation.id
    }
  }
}

# EventBridge -> isolation wiring only exists when GuardDuty does.
resource "aws_cloudwatch_event_target" "guardduty_to_isolate" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.guardduty_findings[0].name
  target_id = "isolate"
  arn       = aws_lambda_function.isolate.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  count = var.enable_guardduty ? 1 : 0

  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.isolate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings[0].arn
}
