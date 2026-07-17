# ---------------------------------------------------------------------------
# The compromise. An attack Lambda plays the operator OFF the box and drives the
# attack ON it via ssm:SendCommand - because the network-plane signatures only
# exist if traffic actually crosses the instance's ENI. The on-box script reads
# the instance role creds from IMDS, pushes a burst of egress bytes to an
# external endpoint, and fans out east-west REJECT probes. See lambda/attack.
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

# Lambda service assume-role trust, reused by the isolation role in respond.tf.
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
  name               = "${var.name_prefix}-s2-attack-lambda"
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
  # Demo-only: exercise the detect->respond pipeline deterministically.
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
  function_name    = "${var.name_prefix}-s2-attack"
  filename         = data.archive_file.attack.output_path
  source_code_hash = data.archive_file.attack.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.attack.arn
  timeout          = 300

  environment {
    variables = {
      INSTANCE_ID    = aws_instance.workload.id
      EXFIL_ENDPOINT = var.exfil_endpoint
      SUBNET_PREFIX  = "10.20.1" # matches local.subnet_cidr in network.tf
      PAYLOAD_MB     = "2"
      EXFIL_CHUNKS   = "10"
      DETECTOR_ID    = var.guardduty_detector_id
    }
  }
}

# The SSM agent registers 1-3 min after boot; a SendCommand before then fails
# with InvalidInstanceId. Gate the auto-fire behind a sleep (the Lambda ALSO
# polls describe_instance_information internally). Same shape as scenario 1's
# key_propagation gate.
resource "time_sleep" "ssm_registration" {
  depends_on      = [aws_instance.workload]
  create_duration = "120s"
}

# Auto-fire on apply. Static input so a plain re-apply never re-fires the
# side-effecting attack. depends_on the detection stack so the tripwire is live
# BEFORE the attack generates its egress signal.
resource "aws_lambda_invocation" "attack" {
  count = var.auto_fire ? 1 : 0

  function_name = aws_lambda_function.attack.function_name
  input         = jsonencode({ trigger = "terraform-apply" })

  depends_on = [
    time_sleep.ssm_registration,
    aws_cloudwatch_log_metric_filter.egress_bytes,
    aws_cloudwatch_metric_alarm.egress_exfil,
    aws_cloudwatch_event_rule.guardduty_findings,
    aws_flow_log.cloudwatch,
  ]
}
