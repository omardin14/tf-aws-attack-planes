# ---------------------------------------------------------------------------
# The compromise. An attack Lambda plays the operator OFF the box and drives the
# attack ON it via ssm:SendCommand - because the DNS-plane signatures only exist
# if the box actually makes the lookups against the Amazon resolver. The on-box
# script beacons (a DGA NXDOMAIN storm) and tunnels (long high-entropy labels on
# TXT), both of which land in the Resolver query logs. See lambda/attack.
#
# The execution role is deliberately narrow: SSM to drive this one box, plus the
# demo-only guardduty:CreateSampleFindings. The "power" in this scenario is the
# INSTANCE role (network.tf), not this one.
# ---------------------------------------------------------------------------
data "archive_file" "attack" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/attack"
  output_path = "${path.module}/build/attack.zip"
}

# Lambda service assume-role trust, reused by the hunter role in detect.tf.
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
  name               = "${var.name_prefix}-s3-attack-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "attack_basic" {
  role       = aws_iam_role.attack.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "attack_role" {
  # Drive the attack on the target box.
  statement {
    sid     = "SendCommandToWorkload"
    effect  = "Allow"
    actions = ["ssm:SendCommand"]
    resources = [
      aws_instance.workload.arn,
      "arn:aws:ssm:${var.region}::document/AWS-RunShellScript",
    ]
  }
  statement {
    sid    = "TrackCommand"
    effect = "Allow"
    actions = [
      "ssm:GetCommandInvocation",
      "ssm:DescribeInstanceInformation",
    ]
    resources = ["*"] # neither action supports resource-level scoping
  }
  # Demo-only: exercise the detect pipeline deterministically.
  statement {
    sid       = "SampleFindings"
    effect    = "Allow"
    actions   = ["guardduty:CreateSampleFindings"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "attack_role" {
  name   = "drive-and-sample"
  role   = aws_iam_role.attack.id
  policy = data.aws_iam_policy_document.attack_role.json
}

resource "aws_lambda_function" "attack" {
  function_name    = "${var.name_prefix}-s3-attack"
  filename         = data.archive_file.attack.output_path
  source_code_hash = data.archive_file.attack.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.attack.arn
  timeout          = 300

  environment {
    variables = {
      INSTANCE_ID      = aws_instance.workload.id
      BEACON_DOMAIN    = var.beacon_domain
      TUNNEL_DOMAIN    = var.tunnel_domain
      BEACON_COUNT     = "60"
      TUNNEL_COUNT     = "40"
      TUNNEL_LABEL_LEN = tostring(var.tunnel_label_len)
      DETECTOR_ID      = var.guardduty_detector_id
    }
  }
}

# The SSM agent registers 1-3 min after boot; a SendCommand before then fails
# with InvalidInstanceId. Gate the auto-fire behind a sleep (the Lambda ALSO
# polls describe_instance_information internally).
resource "time_sleep" "ssm_registration" {
  depends_on      = [aws_instance.workload]
  create_duration = "120s"
}

# Auto-fire on apply. Static input so a plain re-apply never re-fires the
# side-effecting attack. depends_on the detection stack + Resolver logging so
# the tripwire is live and the lookups are captured BEFORE the attack runs.
resource "aws_lambda_invocation" "attack" {
  count = var.auto_fire ? 1 : 0

  function_name = aws_lambda_function.attack.function_name
  input         = jsonencode({ trigger = "terraform-apply" })

  depends_on = [
    time_sleep.ssm_registration,
    aws_route53_resolver_query_log_config_association.this,
    aws_cloudwatch_event_rule.hunter_schedule,
    aws_lambda_function.hunt,
  ]
}
