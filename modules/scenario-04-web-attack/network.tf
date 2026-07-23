# ---------------------------------------------------------------------------
# The target: a deliberately-exposed public web endpoint on top of the shared
# foundation. There is NO compute here - the "app" is an Application Load
# Balancer with a fixed-response listener, so the ALB and WAF still see and log
# every request without an EC2 instance to run or pay for.
#
# The plane here is the WEB plane. Two logs see this traffic, and they answer
# different questions:
#   - WAF logs (-> CloudWatch Logs): what did this IP *try*? Every evaluated
#     request, the rule that matched, and ALLOW/BLOCK/COUNT. The metric-filter
#     alarm (detect.tf) watches this stream.
#   - ALB access logs (-> shared S3 bucket): what actually *reached* the app?
#     The status-code ground truth, queried in Athena (investigate.tf).
#
# Unlike the DNS plane, the response is built into the CONTROL: WAF blocks the
# malicious requests in real time, so there is no separate respond/prevent step.
# ---------------------------------------------------------------------------

locals {
  vpc_cidr = "10.40.0.0/16"

  # ---- ALB access-log schema: ONE ordered source of truth -----------------
  # ALB access logs are space-delimited with quoted sub-fields, so the Glue
  # table (investigate.tf) reads them with a RegexSerDe, NOT the space-delimited
  # LazySimpleSerDe the Flow Logs use. A RegexSerDe matches the WHOLE line, and
  # AWS periodically appends new trailing fields to the ALB log format - so
  # rather than pin all ~30 canonical columns (a too-short regex silently turns
  # EVERY row to NULLs when the format grows), we capture the leading fields the
  # investigation needs and lump the remainder into one `rest` column. The regex
  # capture-group order and this column list are a paired contract: change one,
  # change the other. All columns are `string` (a RegexSerDe requirement).
  #
  # client_ip (#4) and elb_status_code (#11) are the two the blog's status-by-IP
  # query reads; `request` (#15) carries "GET <url> HTTP/1.1" for the scanned-
  # paths query.
  alb_log_regex = "([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \"([^\"]*)\" \"([^\"]*)\" (.*)"

  alb_log_columns = [
    { name = "type", type = "string" },
    { name = "time", type = "string" },
    { name = "elb", type = "string" },
    { name = "client_ip", type = "string" },
    { name = "client_port", type = "string" },
    { name = "target_ip", type = "string" },
    { name = "target_port", type = "string" },
    { name = "request_processing_time", type = "string" },
    { name = "target_processing_time", type = "string" },
    { name = "response_processing_time", type = "string" },
    { name = "elb_status_code", type = "string" },
    { name = "target_status_code", type = "string" },
    { name = "received_bytes", type = "string" },
    { name = "sent_bytes", type = "string" },
    { name = "request", type = "string" },
    { name = "user_agent", type = "string" },
    { name = "rest", type = "string" },
  ]
}

# Two AZs' worth of public subnets: an ALB requires subnets in >= 2 AZs.
data "aws_availability_zones" "available" {
  state = "available"
}

# ---------------------------------------------------------------------------
# VPC + two public subnets + internet gateway. Public so the ALB is internet-
# facing - the whole point of this plane is traffic arriving from the open
# internet at a public endpoint.
# ---------------------------------------------------------------------------
resource "aws_vpc" "this" {
  cidr_block           = local.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-web-vpc" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-web-igw" }
}

resource "aws_subnet" "public" {
  count = 2

  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(local.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "${var.name_prefix}-web-public-${count.index}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = { Name = "${var.name_prefix}-web-public" }
}

resource "aws_route_table_association" "public" {
  count = 2

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# The ALB security group: inbound HTTP from the whole internet (this endpoint
# is MEANT to be attackable), all egress.
# ---------------------------------------------------------------------------
resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-web-alb"
  description = "Public ALB: inbound HTTP from anywhere, all egress."
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTP from the internet."
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-web-alb" }
}

# ---------------------------------------------------------------------------
# The Application Load Balancer + a fixed-response listener - no target group,
# no EC2. The default action returns 404; a rule for path "/" returns 200. So
# the demo produces a legible status-code story: 200 for hits on "/", 404 for
# path scanning, and 403 when WAF blocks a request before it ever reaches here.
# ALB access logs stream to the shared S3 bucket (authorized by the foundation
# bucket policy - no IAM role).
# ---------------------------------------------------------------------------
resource "aws_lb" "this" {
  name               = "${var.name_prefix}-web-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  access_logs {
    bucket  = var.log_bucket_id
    prefix  = "alb-access-logs"
    enabled = true
  }

  tags = { Name = "${var.name_prefix}-web-alb" }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  # Default: anything that isn't "/" is "not found" - that's what turns path
  # scanning into a wall of 404s in the ALB logs.
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "not found"
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener_rule" "root" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 1

  action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "OK"
      status_code  = "200"
    }
  }

  condition {
    path_pattern {
      values = ["/"]
    }
  }
}

# ---------------------------------------------------------------------------
# AWS WAF (WAFv2, REGIONAL scope for an ALB). Two AWS-managed rule groups
# (Common + SQLi) catch the injection/known-bad payloads, and a rate-based rule
# auto-blocks any single IP that crosses the request threshold in a trailing
# 5-minute window. This is the control that makes the web plane unique: it
# BLOCKs the attack as it happens, so the logs' job here is to notify and explain.
# ---------------------------------------------------------------------------
resource "aws_wafv2_web_acl" "this" {
  name        = "${var.name_prefix}-web-acl"
  description = "Demo web ACL: Common + SQLi managed rules plus a rate-based rule."
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "common-rule-set"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "sqli-rule-set"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-sqli"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-limit"
    priority = 3

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-web-acl"
    sampled_requests_enabled   = true
  }

  tags = { Name = "${var.name_prefix}-web-acl" }
}

resource "aws_wafv2_web_acl_association" "this" {
  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

# ---------------------------------------------------------------------------
# WAF logging -> CloudWatch Logs. The log group name MUST start with
# `aws-waf-logs-` (a hard WAF requirement) or the logging configuration is
# rejected. This is the stream the metric-filter alarm (detect.tf) watches.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${var.name_prefix}-s4"
  retention_in_days = 7
}

# WAF logging to a CloudWatch Logs group needs a Logs resource policy letting the
# delivery principal write to aws-waf-logs-* groups. The console creates this for
# you; via Terraform we create it ourselves. Scoped to this account/region.
data "aws_iam_policy_document" "waf_logs_delivery" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:aws-waf-logs-*:*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${var.region}:${var.account_id}:*"]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "waf_logs_delivery" {
  policy_name     = "${var.name_prefix}-s4-waf-logs-delivery"
  policy_document = data.aws_iam_policy_document.waf_logs_delivery.json
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = aws_wafv2_web_acl.this.arn

  depends_on = [aws_cloudwatch_log_resource_policy.waf_logs_delivery]
}
