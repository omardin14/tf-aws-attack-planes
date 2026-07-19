# ---------------------------------------------------------------------------
# The tripwire - and the departure from scenarios 1 & 2. DNS abuse is a PATTERN
# OVER A WINDOW (long labels, a burst of NXDOMAIN to one domain), which a raw
# metric filter reads poorly - and besides, Resolver logs go only to S3 here, so
# there's no CloudWatch stream to filter. So the always-on detector is a
# SCHEDULED HUNTER Lambda: EventBridge runs it every few minutes, it queries the
# last window of Resolver logs in Athena for the tunnelling/beacon signatures,
# and publishes to the shared SNS topic on a hit. See lambda/hunt.
#
# A GuardDuty -> EventBridge -> SNS path is also created (gated on enable_guardduty)
# for the optional DNS-native managed findings.
# ---------------------------------------------------------------------------
data "archive_file" "hunt" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/hunt"
  output_path = "${path.module}/build/hunt.zip"
}

resource "aws_iam_role" "hunt" {
  name               = "${var.name_prefix}-s3-hunter-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "hunt_basic" {
  role       = aws_iam_role.hunt.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "hunt_role" {
  # Run the hunt queries in the shared workgroup.
  statement {
    sid    = "RunAthena"
    effect = "Allow"
    actions = [
      "athena:StartQueryExecution",
      "athena:GetQueryExecution",
      "athena:GetQueryResults",
      "athena:StopQueryExecution",
    ]
    resources = ["*"] # scoped in practice by the Glue/S3 grants below
  }
  # Athena reads the table definition from Glue.
  statement {
    sid    = "ReadGlue"
    effect = "Allow"
    actions = [
      "glue:GetTable",
      "glue:GetDatabase",
      "glue:GetPartition",
      "glue:GetPartitions",
    ]
    resources = ["*"]
  }
  # Read the Resolver logs and read/write Athena results in the shared bucket.
  statement {
    sid       = "ListLogBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = ["arn:aws:s3:::${var.log_bucket_id}"]
  }
  statement {
    sid    = "ReadWriteObjects"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::${var.log_bucket_id}/route53-resolver/*",
      "arn:aws:s3:::${var.log_bucket_id}/athena-results/*",
    ]
  }
  # Alert on a hit.
  statement {
    sid       = "Publish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [var.sns_topic_arn]
  }
}

resource "aws_iam_role_policy" "hunt_role" {
  name   = "run-dns-hunt"
  role   = aws_iam_role.hunt.id
  policy = data.aws_iam_policy_document.hunt_role.json
}

resource "aws_lambda_function" "hunt" {
  function_name    = "${var.name_prefix}-s3-hunter"
  filename         = data.archive_file.hunt.output_path
  source_code_hash = data.archive_file.hunt.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.hunt.arn
  timeout          = 120

  environment {
    variables = {
      DATABASE           = var.glue_database_name
      TABLE              = aws_glue_catalog_table.resolver_logs.name
      WORKGROUP          = var.athena_workgroup_name
      ATHENA_OUTPUT      = var.athena_results_location
      SNS_TOPIC_ARN      = var.sns_topic_arn
      WINDOW_MINUTES     = tostring(var.window_minutes)
      TUNNEL_LABEL_LEN   = tostring(var.tunnel_label_len)
      NXDOMAIN_THRESHOLD = tostring(var.nxdomain_threshold)
    }
  }
}

# EventBridge schedule -> hunter. Fires whenever the scenario is deployed; the
# module is itself scenario-gated at the root, so this only exists when
# scenario_03_enabled = true.
resource "aws_cloudwatch_event_rule" "hunter_schedule" {
  name                = "${var.name_prefix}-s3-dns-hunter-schedule"
  description         = "Run the DNS beacon/tunnelling hunter over the last window of Resolver query logs."
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "hunter" {
  rule      = aws_cloudwatch_event_rule.hunter_schedule.name
  target_id = "dns-hunter"
  arn       = aws_lambda_function.hunt.arn
}

resource "aws_lambda_permission" "allow_schedule" {
  statement_id  = "AllowEventBridgeSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.hunt.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.hunter_schedule.arn
}

# ---------------------------------------------------------------------------
# GuardDuty findings -> EventBridge -> SNS (notify). GuardDuty analyses DNS
# through the Amazon resolver itself, so with it enabled you get DNS-native
# findings (C&CActivity.B!DNS, DGADomainRequest, DNSDataExfiltration) independent
# of the hunter above. Gated on enable_guardduty (not on the Free Tier).
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count = var.enable_guardduty ? 1 : 0

  name        = "${var.name_prefix}-s3-guardduty-findings"
  description = "Route GuardDuty findings to the shared alert topic."
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
