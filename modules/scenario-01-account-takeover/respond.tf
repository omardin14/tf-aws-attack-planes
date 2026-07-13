# ---------------------------------------------------------------------------
# Quarantine Lambda: EventBridge (GuardDuty finding) -> attach AWSDenyAll to the
# compromised user. Buys a human time while they catch up.
# ---------------------------------------------------------------------------
data "archive_file" "quarantine" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/quarantine"
  output_path = "${path.module}/build/quarantine.zip"
}

resource "aws_iam_role" "quarantine" {
  name               = "${var.name_prefix}-quarantine-lambda"
  assume_role_policy = data.aws_iam_policy_document.attack_assume.json
}

resource "aws_iam_role_policy_attachment" "quarantine_basic" {
  role       = aws_iam_role.quarantine.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "quarantine" {
  statement {
    effect    = "Allow"
    actions   = ["iam:AttachUserPolicy"]
    resources = ["arn:aws:iam::${var.account_id}:user/${var.name_prefix}-*"]
  }
}

resource "aws_iam_role_policy" "quarantine" {
  name   = "attach-deny-all"
  role   = aws_iam_role.quarantine.id
  policy = data.aws_iam_policy_document.quarantine.json
}

resource "aws_lambda_function" "quarantine" {
  function_name    = "${var.name_prefix}-quarantine"
  filename         = data.archive_file.quarantine.output_path
  source_code_hash = data.archive_file.quarantine.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.quarantine.arn
  timeout          = 30

  environment {
    variables = {
      LEAKED_USERNAME = local.leaked_user_name
    }
  }
}

resource "aws_cloudwatch_event_target" "guardduty_to_quarantine" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "quarantine"
  arn       = aws_lambda_function.quarantine.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.quarantine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}

# ---------------------------------------------------------------------------
# Cleanup Lambda: purges the out-of-band backdoor users the attack created, so
# `terraform destroy` doesn't leave live credentials behind. Invoked by the
# destroy-time provisioner below.
# ---------------------------------------------------------------------------
data "archive_file" "cleanup" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/cleanup"
  output_path = "${path.module}/build/cleanup.zip"
}

resource "aws_iam_role" "cleanup" {
  name               = "${var.name_prefix}-cleanup-lambda"
  assume_role_policy = data.aws_iam_policy_document.attack_assume.json
}

resource "aws_iam_role_policy_attachment" "cleanup_basic" {
  role       = aws_iam_role.cleanup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "cleanup" {
  statement {
    sid       = "FindPersistenceUsers"
    effect    = "Allow"
    actions   = ["iam:ListUsers"]
    resources = ["*"]
  }
  statement {
    sid    = "PurgePersistenceUsers"
    effect = "Allow"
    actions = [
      "iam:ListAccessKeys",
      "iam:DeleteAccessKey",
      "iam:ListAttachedUserPolicies",
      "iam:DetachUserPolicy",
      "iam:ListUserPolicies",
      "iam:DeleteUserPolicy",
      "iam:DeleteUser",
    ]
    resources = ["arn:aws:iam::${var.account_id}:user/${local.persist_prefix}-*"]
  }
}

resource "aws_iam_role_policy" "cleanup" {
  name   = "purge-persistence"
  role   = aws_iam_role.cleanup.id
  policy = data.aws_iam_policy_document.cleanup.json
}

resource "aws_lambda_function" "cleanup" {
  function_name    = "${var.name_prefix}-cleanup"
  filename         = data.archive_file.cleanup.output_path
  source_code_hash = data.archive_file.cleanup.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.cleanup.arn
  timeout          = 60

  environment {
    variables = {
      PERSIST_PREFIX = local.persist_prefix
    }
  }
}

# Fire the cleanup Lambda on destroy. Destroy-time provisioners can only see
# self.triggers, so the function name is stashed there. Needs the AWS CLI on the
# machine running `terraform destroy`.
resource "null_resource" "cleanup_on_destroy" {
  triggers = {
    function_name = aws_lambda_function.cleanup.function_name
    region        = var.region
  }

  provisioner "local-exec" {
    when    = destroy
    command = "aws lambda invoke --function-name ${self.triggers.function_name} --region ${self.triggers.region} /dev/null"
  }

  depends_on = [aws_lambda_function.cleanup, aws_iam_role_policy.cleanup]
}
