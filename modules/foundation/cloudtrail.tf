# Multi-region CloudTrail with log-file validation, delivering to BOTH:
#   - S3 (retention + Athena forensics), and
#   - CloudWatch Logs (real-time metric-filter alarms).
# This is the "turn on both CloudWatch & S3" advice from the blog, in Terraform.

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${var.name_prefix}"
  retention_in_days = 90
}

# Role CloudTrail assumes to write into the log group.
data "aws_iam_policy_document" "trail_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "trail_to_cwl" {
  name               = "${var.name_prefix}-cloudtrail-to-cwl"
  assume_role_policy = data.aws_iam_policy_document.trail_assume.json
}

data "aws_iam_policy_document" "trail_to_cwl" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:*"]
  }
}

resource "aws_iam_role_policy" "trail_to_cwl" {
  name   = "deliver-to-cwl"
  role   = aws_iam_role.trail_to_cwl.id
  policy = data.aws_iam_policy_document.trail_to_cwl.json
}

resource "aws_cloudtrail" "this" {
  name           = local.trail_name
  s3_bucket_name = aws_s3_bucket.logs.id

  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true

  # The log-group ARN handed to CloudTrail MUST end in ":*" (the log-stream glob),
  # not the bare group ARN.
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_to_cwl.arn

  # The bucket policy must exist before the trail, or CloudTrail returns
  # InsufficientS3BucketPolicyException at create time.
  depends_on = [aws_s3_bucket_policy.trail]
}
