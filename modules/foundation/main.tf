data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  region        = data.aws_region.current.name
  log_bucket    = "${var.name_prefix}-audit-logs-${local.account_id}"
  trail_name    = "${var.name_prefix}-trail"
  athena_wg     = "${var.name_prefix}-investigations"
  glue_db       = replace("${var.name_prefix}_audit", "-", "_")
  athena_prefix = "athena-results"
}
