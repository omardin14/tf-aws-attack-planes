# ---------------------------------------------------------------------------
# The answer layer - two logs, two tools, two questions.
#
#   "What did this IP TRY?"          -> WAF logs, in CloudWatch, via a saved
#                                       Logs Insights query (aws_cloudwatch_query
#                                       _definition below).
#   "What actually REACHED the app?" -> ALB access logs, in S3, via Athena (the
#                                       Glue table + named queries below).
#
# The ALB table uses partition projection (no crawler / MSCK REPAIR needed).
# ---------------------------------------------------------------------------

locals {
  # ALB access logs land under
  # alb-access-logs/AWSLogs/<account>/elasticloadbalancing/<region>/y/m/d.
  # The region is fixed at apply time, so it's baked into the location and we
  # project on date only.
  alb_logs_location = "s3://${var.log_bucket_id}/alb-access-logs/AWSLogs/${var.account_id}/elasticloadbalancing/${var.region}"
}

resource "aws_glue_catalog_table" "alb_access_logs" {
  name          = "alb_access_logs"
  database_name = var.glue_database_name
  table_type    = "EXTERNAL_TABLE"

  partition_keys {
    name = "date"
    type = "string"
  }

  parameters = {
    "EXTERNAL"                      = "TRUE"
    "projection.enabled"            = "true"
    "projection.date.type"          = "date"
    "projection.date.range"         = "2024/01/01,NOW"
    "projection.date.format"        = "yyyy/MM/dd"
    "projection.date.interval"      = "1"
    "projection.date.interval.unit" = "DAYS"
    "storage.location.template"     = "${local.alb_logs_location}/$${date}"
  }

  storage_descriptor {
    location      = local.alb_logs_location
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    # ALB access logs are space-delimited with quoted sub-fields -> RegexSerDe,
    # NOT the LazySimpleSerDe the Flow Logs use. local.alb_log_regex's capture
    # groups line up 1:1 with local.alb_log_columns (the contract in network.tf).
    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.serde2.RegexSerDe"
      parameters = {
        "input.regex" = local.alb_log_regex
      }
    }

    dynamic "columns" {
      for_each = local.alb_log_columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
  }
}

# --- Saved investigation queries (created, not executed) ---------------------

resource "aws_athena_named_query" "alb_status_by_ip" {
  name        = "s04-01-alb-status-by-ip"
  description = "The response-code shape per IP - a wall of one status from one IP tells you the intent (403 = WAF held the line, 404 = recon got through, 200 = it's working, and that's the problem)."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- The canonical web-plane query. One client_ip dominating a single status
    -- column is the story: 403 = WAF blocked it, 404 = path scanning that got
    -- through the rules, 200 = requests that worked (credential stuffing looks
    -- like this).
    SELECT client_ip,
           elb_status_code,
           COUNT(*) AS requests
    FROM alb_access_logs
    GROUP BY client_ip, elb_status_code
    ORDER BY requests DESC
    LIMIT 20;
  SQL
}

resource "aws_athena_named_query" "alb_scanned_paths" {
  name        = "s04-02-alb-scanned-paths"
  description = "The paths an attacker probed that weren't blocked - a wall of 404s across many URLs from one IP is reconnaissance, and now you know exactly which paths to go harden."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- `request` holds "GET <url> HTTP/1.1"; split out the URL. 404s that weren't
    -- blocked are reconnaissance that got past the rules.
    SELECT split_part(request, ' ', 2) AS url,
           elb_status_code,
           COUNT(*)                    AS requests
    FROM alb_access_logs
    WHERE elb_status_code = '404'
    GROUP BY split_part(request, ' ', 2), elb_status_code
    ORDER BY requests DESC
    LIMIT 25;
  SQL
}

# --- The WAF "what did this IP try?" view, in CloudWatch Logs Insights --------
# WAF logs live in CloudWatch, not S3, so this question is a Logs Insights query,
# not Athena. Saved as a query definition so it's one click in the console.
resource "aws_cloudwatch_query_definition" "waf_blocks_by_ip" {
  name            = "${var.name_prefix}/s04-waf-blocks-by-ip"
  log_group_names = [aws_cloudwatch_log_group.waf.name]

  query_string = <<-QUERY
    fields httpRequest.clientIp, httpRequest.uri, terminatingRuleId, action
    | filter action = "BLOCK"
    | stats count() as hits by httpRequest.clientIp, terminatingRuleId
    | sort hits desc
  QUERY
}
