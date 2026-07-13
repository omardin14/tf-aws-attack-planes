locals {
  leaked_user_name = "${var.name_prefix}-leaked-ci-user"
  persist_prefix   = "${var.name_prefix}-persist"
}

# ---------------------------------------------------------------------------
# The "leaked" identity: a long-lived key on a deliberately over-permissive
# CI user. This is what ends up in a public repo / a phished dotfile.
# ---------------------------------------------------------------------------
resource "aws_iam_user" "leaked" {
  name          = local.leaked_user_name
  force_destroy = true # drop the access key + backdoors-on-self on destroy
}

data "aws_iam_policy_document" "leaked" {
  statement {
    sid       = "TooMuchTrust"
    effect    = "Allow"
    actions   = ["iam:*", "sts:*", "s3:List*"]
    resources = ["*"]
  }
}

resource "aws_iam_user_policy" "leaked" {
  name   = "leaked-ci-permissions"
  user   = aws_iam_user.leaked.name
  policy = data.aws_iam_policy_document.leaked.json
}

resource "aws_iam_access_key" "leaked" {
  user = aws_iam_user.leaked.name
}

# ---------------------------------------------------------------------------
# Attack Lambda. Signs the attack chain with the leaked key (via env vars);
# the execution role is intentionally near-powerless so a stray default-client
# call fails loudly instead of being mis-attributed to the role.
# ---------------------------------------------------------------------------
data "archive_file" "attack" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/attack"
  output_path = "${path.module}/build/attack.zip"
}

data "aws_iam_policy_document" "attack_assume" {
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
  name               = "${var.name_prefix}-attack-lambda"
  assume_role_policy = data.aws_iam_policy_document.attack_assume.json
}

resource "aws_iam_role_policy_attachment" "attack_basic" {
  role       = aws_iam_role.attack.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# The ONLY AWS permission the role itself gets: firing the demo sample finding.
data "aws_iam_policy_document" "attack_role" {
  statement {
    effect    = "Allow"
    actions   = ["guardduty:CreateSampleFindings"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "attack_role" {
  name   = "sample-findings-only"
  role   = aws_iam_role.attack.id
  policy = data.aws_iam_policy_document.attack_role.json
}

resource "aws_lambda_function" "attack" {
  function_name    = "${var.name_prefix}-attack"
  filename         = data.archive_file.attack.output_path
  source_code_hash = data.archive_file.attack.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.attack.arn
  timeout          = 120

  environment {
    variables = {
      # Intentionally insecure: the leaked secret is passed in plaintext. That
      # is the whole point of the scenario, and the secret is already in TF state.
      LEAKED_AK_ID   = aws_iam_access_key.leaked.id
      LEAKED_SECRET  = aws_iam_access_key.leaked.secret
      PERSIST_PREFIX = local.persist_prefix
      DETECTOR_ID    = var.guardduty_detector_id
    }
  }
}

# Belt-and-suspenders against IAM eventual consistency: give the new key ~15s to
# propagate before we invoke. The Lambda ALSO retries internally.
resource "time_sleep" "key_propagation" {
  depends_on      = [aws_iam_access_key.leaked]
  create_duration = "15s"
}

# Auto-fire on apply. Static input so it never re-fires the side-effecting attack
# on a plain re-apply. depends_on the detection stack so the tripwires are live
# BEFORE the attack generates its signal.
resource "aws_lambda_invocation" "attack" {
  count = var.auto_fire ? 1 : 0

  function_name = aws_lambda_function.attack.function_name
  input         = jsonencode({ trigger = "terraform-apply" })

  depends_on = [
    time_sleep.key_propagation,
    aws_cloudwatch_log_metric_filter.access_denied,
    aws_cloudwatch_log_metric_filter.iam_persistence,
    aws_cloudwatch_event_rule.guardduty_findings,
  ]
}
