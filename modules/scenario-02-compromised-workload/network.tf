# ---------------------------------------------------------------------------
# The target: a tiny attackable network on top of the shared foundation. One
# EC2 instance in a public subnet, carrying an over-permissive instance role -
# the credential an attacker steals once they land on the box. IMDSv2 is
# enforced (the right default), which makes the scenario's point that it does
# NOT stop what happens after code execution.
#
# VPC Flow Logs are enabled on the VPC with a custom format, delivered to BOTH
# the shared S3 log bucket (forensics/Athena) and a dedicated CloudWatch log
# group (the metric-filter alarm). One local.flow_log_format feeds both so the
# CloudWatch metric-filter positions and the S3/Glue columns can never drift.
# ---------------------------------------------------------------------------

locals {
  vpc_cidr    = "10.20.0.0/16"
  subnet_cidr = "10.20.1.0/24"

  # ---- Flow-log schema: ONE ordered source of truth ----------------------
  # These 18 fields, in THIS order, are the contract tying together the flow-log
  # format, the Glue table columns (investigate.tf), and the positional
  # CloudWatch metric-filter pattern (detect.tf). Change one, change all three.
  #
  # In the format string every "$" is doubled to "$$" so Terraform passes the
  # literal "${field}" token through to VPC Flow Logs instead of interpolating.
  flow_log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${flow-direction} $${pkt-srcaddr} $${pkt-dstaddr} $${instance-id}"

  flow_log_columns = [
    { name = "version", type = "int" },
    { name = "account_id", type = "string" },
    { name = "interface_id", type = "string" },
    { name = "srcaddr", type = "string" },
    { name = "dstaddr", type = "string" },
    { name = "srcport", type = "int" },
    { name = "dstport", type = "int" },
    { name = "protocol", type = "int" },
    { name = "packets", type = "bigint" },
    { name = "bytes", type = "bigint" },
    { name = "start", type = "bigint" },
    { name = "end", type = "bigint" },
    { name = "action", type = "string" },
    { name = "log_status", type = "string" },
    { name = "flow_direction", type = "string" },
    { name = "pkt_srcaddr", type = "string" },
    { name = "pkt_dstaddr", type = "string" },
    { name = "instance_id", type = "string" },
  ]
}

# Latest Amazon Linux 2023 AMI (SSM agent preinstalled) via the public SSM
# parameter, so we never hard-code a region-specific AMI id.
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# ---------------------------------------------------------------------------
# VPC + public subnet + internet gateway. Public subnet (not NAT) so the box
# egresses directly - with no NAT in path, pkt-srcaddr == srcaddr for its flows.
# ---------------------------------------------------------------------------
resource "aws_vpc" "this" {
  cidr_block           = local.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-workload-vpc" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-workload-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.subnet_cidr
  map_public_ip_on_launch = true

  tags = { Name = "${var.name_prefix}-workload-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = { Name = "${var.name_prefix}-workload-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# Security groups. The workload SG allows all egress (so the exfil is possible
# and SSM can reach the endpoints) and no inbound. The isolation SG has NO
# rules at all - the respond Lambda swaps the instance into it to cut it off.
# ---------------------------------------------------------------------------
resource "aws_security_group" "workload" {
  name        = "${var.name_prefix}-workload"
  description = "Workload instance: all egress, no ingress."
  vpc_id      = aws_vpc.this.id

  egress {
    description = "All outbound (internet + SSM endpoints)."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-workload" }
}

resource "aws_security_group" "isolation" {
  name        = "${var.name_prefix}-workload-isolation"
  description = "Quarantine SG: no ingress, no egress. The respond Lambda swaps the compromised instance into this."
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-workload-isolation" }
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
  name               = "${var.name_prefix}-workload-role"
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
  name   = "over-permissive-workload"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance.json
}

resource "aws_iam_role_policy_attachment" "instance_ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name_prefix}-workload-profile"
  role = aws_iam_role.instance.name
}

# A just-created instance profile / role attachment is eventually consistent;
# launching the instance too soon fails with "Invalid IAM Instance Profile".
# Same class of guard as scenario 1's key-propagation sleep.
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
# creds (defeats naive SSRF) but does nothing once the attacker has code exec.
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

  tags = { Name = "${var.name_prefix}-workload" }

  # The respond Lambda swaps this instance's SG out-of-band during a live
  # response; don't let that show up as perpetual drift we fight on every plan.
  # A `terraform apply` still restores the baseline SG (the reset) on demand.
  lifecycle {
    ignore_changes = [vpc_security_group_ids]
  }
}

# ---------------------------------------------------------------------------
# VPC Flow Logs. Both destinations share local.flow_log_format so CloudWatch
# (the alarm) and S3 (Athena) see byte-identical records. traffic_type = ALL is
# mandatory so the REJECT lateral-movement records exist. max_aggregation_
# interval = 60 so the egress spike surfaces within a minute, not ~10.
# ---------------------------------------------------------------------------

# --- CloudWatch destination (metric-filter alarm) ---
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/${var.name_prefix}/scenario-02/vpc-flow-logs"
  retention_in_days = 14
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${var.name_prefix}-flow-logs-cw"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

data "aws_iam_policy_document" "flow_logs_cw" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.flow_logs.arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow_logs_cw" {
  name   = "deliver-flow-logs"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs_cw.json
}

resource "aws_flow_log" "cloudwatch" {
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  log_format               = local.flow_log_format
  max_aggregation_interval = 60

  tags = { Name = "${var.name_prefix}-flow-logs-cw" }
}

# --- S3 destination (Athena forensics) ---
# No IAM role: delivery is authorized by the foundation bucket policy
# (delivery.logs.amazonaws.com). Objects land under
# vpc-flow-logs/AWSLogs/<account>/vpcflowlogs/<region>/yyyy/mm/dd/...
resource "aws_flow_log" "s3" {
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = "${var.log_bucket_arn}/vpc-flow-logs"
  log_format               = local.flow_log_format
  max_aggregation_interval = 60

  tags = { Name = "${var.name_prefix}-flow-logs-s3" }
}
