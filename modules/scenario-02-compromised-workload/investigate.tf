# ---------------------------------------------------------------------------
# The answer layer. A Glue table over the VPC Flow Logs in S3 (partition
# projection, so no crawler / MSCK REPAIR) plus the saved queries the blog walks
# through. This is the first cross-plane story: the egress question ("where did
# the data go?") isn't an API call, so CloudTrail can't answer it - Flow Logs can.
# ---------------------------------------------------------------------------

locals {
  # S3 flow logs land under <prefix>/AWSLogs/<account>/vpcflowlogs/<region>/y/m/d.
  flow_logs_location = "s3://${var.log_bucket_id}/vpc-flow-logs/AWSLogs/${var.account_id}/vpcflowlogs"

  # Regions the projection enumerates so no partition load is ever needed. Same
  # list as scenario 1's CloudTrail table.
  projection_regions = join(",", [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "sa-east-1", "ca-central-1",
  ])
}

resource "aws_glue_catalog_table" "flow_logs" {
  name          = "vpc_flow_logs"
  database_name = var.glue_database_name
  table_type    = "EXTERNAL_TABLE"

  partition_keys {
    name = "region"
    type = "string"
  }
  partition_keys {
    name = "date"
    type = "string"
  }

  parameters = {
    "EXTERNAL"                      = "TRUE"
    "skip.header.line.count"        = "1" # each S3 flow-log object has a header row
    "projection.enabled"            = "true"
    "projection.region.type"        = "enum"
    "projection.region.values"      = local.projection_regions
    "projection.date.type"          = "date"
    "projection.date.range"         = "2024/01/01,NOW"
    "projection.date.format"        = "yyyy/MM/dd"
    "projection.date.interval"      = "1"
    "projection.date.interval.unit" = "DAYS"
    "storage.location.template"     = "${local.flow_logs_location}/$${region}/$${date}"
  }

  storage_descriptor {
    location      = local.flow_logs_location
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
      parameters = {
        "field.delim"               = " "
        "serialization.format"      = " "
        "serialization.null.format" = "-" # flow logs emit "-" for absent fields
      }
    }

    dynamic "columns" {
      for_each = local.flow_log_columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
  }
}

# --- Saved investigation queries (created, not executed) ---------------------

resource "aws_athena_named_query" "top_talkers" {
  name        = "s02-01-top-talkers-egress-bytes"
  description = "Who are my top talkers to the outside world? A single external destination hoovering the bytes column is the exfil, in one row."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- The canonical network-plane query. A single dstaddr dominating total_bytes
    -- on ACCEPTed egress is your exfiltration channel. Cross-reference the
    -- instance_id in CloudTrail for the identity half of the story.
    SELECT pkt_srcaddr AS host,
           dstaddr     AS destination,
           dstport,
           SUM(bytes)  AS total_bytes,
           SUM(packets) AS total_packets
    FROM vpc_flow_logs
    WHERE flow_direction = 'egress'
      AND action = 'ACCEPT'
    GROUP BY pkt_srcaddr, dstaddr, dstport
    ORDER BY total_bytes DESC
    LIMIT 25;
  SQL
}

resource "aws_athena_named_query" "reject_probe" {
  name        = "s02-02-reject-lateral-movement-probe"
  description = "The lateral-movement probe: REJECTed connection attempts to neighbours - an attacker knocking on doors that were, thankfully, locked."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- A fan of REJECTs across internal addresses/ports from one source is a
    -- host exploring what else it can reach. Concentrated on 22/445/3389 it's
    -- lateral-movement probing.
    SELECT srcaddr,
           dstport,
           COUNT(*)              AS attempts,
           COUNT(DISTINCT dstaddr) AS targets_touched
    FROM vpc_flow_logs
    WHERE action = 'REJECT'
    GROUP BY srcaddr, dstport
    ORDER BY attempts DESC
    LIMIT 50;
  SQL
}

resource "aws_athena_named_query" "instance_egress_timeline" {
  name        = "s02-03-compromised-instance-egress-timeline"
  description = "Egress from the compromised instance over time - line this up with the alarm timestamp."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- Pivot from the box (instance_id) to what it shipped, when. The bytes column
    -- climbing against one destination is the exfil unfolding.
    SELECT from_unixtime(start) AS window_start,
           dstaddr,
           dstport,
           bytes
    FROM vpc_flow_logs
    WHERE instance_id = '${aws_instance.workload.id}'
      AND flow_direction = 'egress'
      AND action = 'ACCEPT'
    ORDER BY start;
  SQL
}
