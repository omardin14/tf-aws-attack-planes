# ---------------------------------------------------------------------------
# The target: a tiny attackable network on top of the shared foundation. One
# EC2 instance in a public subnet, carrying an over-permissive instance role -
# the credential an attacker steals once they land on the box. IMDSv2 is
# enforced (the right default), which makes the scenario's point that it does
# NOT stop what happens after code execution.
#
# The plane here is DNS. Route 53 Resolver query logging is enabled on the VPC,
# delivering to the shared S3 log bucket. Unlike Flow Logs (which can fan out to
# BOTH CloudWatch and S3), a VPC can have only ONE Resolver query-logging
# destination - so this scenario sends to S3 and detects with a scheduled
# Athena hunter (detect.tf) rather than a CloudWatch metric-filter alarm.
# ---------------------------------------------------------------------------

locals {
  vpc_cidr    = "10.30.0.0/16"
  subnet_cidr = "10.30.1.0/24"

  # ---- Resolver query-log schema: ONE ordered source of truth -------------
  # Route 53 Resolver query logs are gzipped JSON (one object per line). These
  # columns map by name onto the JSON keys AWS emits; the same list drives the
  # Glue table columns in investigate.tf via a dynamic block, so the table can
  # never drift from this contract. The JSON SerDe matches on name and IGNORES
  # unmapped keys, so this is a safe subset: we deliberately omit `answers` (a
  # JSON array no query needs - typing an array as a scalar trips the SerDe) and
  # only list the firewall_* field we actually query. Missing keys (the
  # firewall_* fields only appear once DNS Firewall is on) read as NULL.
  resolver_log_columns = [
    { name = "version", type = "string" },
    { name = "account_id", type = "string" },
    { name = "region", type = "string" },
    { name = "vpc_id", type = "string" },
    { name = "query_timestamp", type = "string" },
    { name = "query_name", type = "string" },
    { name = "query_type", type = "string" },
    { name = "query_class", type = "string" },
    { name = "rcode", type = "string" },
    { name = "srcaddr", type = "string" },
    { name = "srcport", type = "string" },
    { name = "transport", type = "string" },
    { name = "srcids", type = "struct<instance:string>" },
    { name = "firewall_rule_action", type = "string" },
  ]
}

# Latest Amazon Linux 2023 AMI (SSM agent preinstalled) via the public SSM
# parameter, so we never hard-code a region-specific AMI id.
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# ---------------------------------------------------------------------------
# VPC + public subnet + internet gateway. DNS support/hostnames ON so the box
# resolves through the Amazon-provided resolver (169.254.169.253) - which is
# exactly the traffic Resolver query logging captures.
# ---------------------------------------------------------------------------
resource "aws_vpc" "this" {
  cidr_block           = local.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-dns-workload-vpc" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-dns-workload-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.subnet_cidr
  map_public_ip_on_launch = true

  tags = { Name = "${var.name_prefix}-dns-workload-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = { Name = "${var.name_prefix}-dns-workload-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# Security group: all egress (so SSM can reach the box and the box can install
# bind-utils / reach the resolver), no inbound. There is no isolation SG here -
# this plane has no automated responder (see prevent.tf for the DNS-Firewall
# 'prevent' control instead).
# ---------------------------------------------------------------------------
resource "aws_security_group" "workload" {
  name        = "${var.name_prefix}-dns-workload"
  description = "DNS workload instance: all egress, no ingress."
  vpc_id      = aws_vpc.this.id

  egress {
    description = "All outbound (internet + SSM endpoints)."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-dns-workload" }
}

# ---------------------------------------------------------------------------
# The over-permissive instance role: the "juicy" credential the attacker steals
# from IMDS. AmazonSSMManagedInstanceCore is added so the attack Lambda can
# drive the box via ssm:SendCommand (and so you can Session-Manager onto it).
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "instance_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "${var.name_prefix}-dns-workload-role"
  assume_role_policy = data.aws_iam_policy_document.instance_assume.json
}

data "aws_iam_policy_document" "instance" {
  statement {
    sid    = "TooMuchTrust"
    effect = "Allow"
    actions = [
      "s3:*",
      "secretsmanager:GetSecretValue",
      "iam:List*",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "instance" {
  name   = "over-permissive-dns-workload"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance.json
}

resource "aws_iam_role_policy_attachment" "instance_ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name_prefix}-dns-workload-profile"
  role = aws_iam_role.instance.name
}

# A just-created instance profile / role attachment is eventually consistent;
# launching the instance too soon fails with "Invalid IAM Instance Profile".
resource "time_sleep" "profile_propagation" {
  depends_on = [
    aws_iam_instance_profile.instance,
    aws_iam_role_policy.instance,
    aws_iam_role_policy_attachment.instance_ssm,
  ]
  create_duration = "15s"
}

# ---------------------------------------------------------------------------
# The workload. IMDSv2 enforced (http_tokens = required, hop limit 1) - the
# right hardening, and the scenario's point: it raises the bar for STEALING the
# creds but does nothing once the attacker has code exec.
# ---------------------------------------------------------------------------
resource "aws_instance" "workload" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.workload.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  depends_on = [time_sleep.profile_propagation]

  tags = { Name = "${var.name_prefix}-dns-workload" }
}

# ---------------------------------------------------------------------------
# Route 53 Resolver query logging -> shared S3 log bucket. Objects land under
# route53-resolver/AWSLogs/<account>/vpcdnsquerylogs/<vpc-id>/yyyy/mm/dd/...
# Delivery is authorized by the foundation bucket policy (delivery.logs.
# amazonaws.com); config creation validates that policy, so the module block in
# the root sequences this whole module AFTER the foundation via depends_on.
# ---------------------------------------------------------------------------
resource "aws_route53_resolver_query_log_config" "this" {
  name            = "${var.name_prefix}-s3-resolver-qlog"
  destination_arn = "${var.log_bucket_arn}/route53-resolver"

  tags = { Name = "${var.name_prefix}-s3-resolver-qlog" }
}

resource "aws_route53_resolver_query_log_config_association" "this" {
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.this.id
  resource_id                  = aws_vpc.this.id
}
