# ---------------------------------------------------------------------------
# The answer layer. A Glue table over the Route 53 Resolver query logs in S3
# (partition projection, so no crawler / MSCK REPAIR) plus the saved queries the
# blog walks through - the same ones the scheduled hunter (detect.tf) runs, so
# you can also run them by hand.
#
# Resolver query logs are gzipped JSON (one object per line), so this table uses
# a JSON SerDe - unlike scenario 2's space-delimited Flow Logs. The columns come
# from local.resolver_log_columns (network.tf), matched by name onto the JSON
# keys AWS emits.
# ---------------------------------------------------------------------------

locals {
  # S3 layout: <prefix>/AWSLogs/<account>/vpcdnsquerylogs/<vpc-id>/yyyy/mm/dd/...
  # vpc-id is known at apply time, so we embed it and project only on date.
  resolver_logs_location = "s3://${var.log_bucket_id}/route53-resolver/AWSLogs/${var.account_id}/vpcdnsquerylogs/${aws_vpc.this.id}"
}

resource "aws_glue_catalog_table" "resolver_logs" {
  name          = "route53_resolver_logs"
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
    "storage.location.template"     = "${local.resolver_logs_location}/$${date}"
  }

  storage_descriptor {
    location      = local.resolver_logs_location
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters = {
        "ignore.malformed.json" = "true"
      }
    }

    dynamic "columns" {
      for_each = local.resolver_log_columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
  }
}

# --- Saved investigation queries (created, not executed) ---------------------

resource "aws_athena_named_query" "dns_tunnelling" {
  name        = "s03-01-dns-tunnelling"
  description = "DNS tunnelling: long, high-entropy first labels on TXT/NULL records pointed at one domain - a file transfer wearing a DNS costume."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- Normal DNS is short and boring, so abnormally long first labels are the
    -- tell. Long, high-entropy labels hammering a single domain over TXT/NULL
    -- is data leaving, one query at a time.
    SELECT query_name,
           length(split_part(query_name, '.', 1)) AS first_label_len,
           COUNT(*)                                AS lookups
    FROM route53_resolver_logs
    WHERE query_type IN ('TXT', 'NULL')
    GROUP BY query_name
    ORDER BY first_label_len DESC, lookups DESC
    LIMIT 20;
  SQL
}

resource "aws_athena_named_query" "dga_beacon" {
  name        = "s03-02-dga-beacon-nxdomain"
  description = "The DGA beacon: one parent domain with an outsized share of NXDOMAIN responses - malware cycling through candidate C2 domains looking for a live one."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- Group by the parent domain (last two labels) and count NXDOMAIN responses.
    -- A workload generating dozens of failed lookups to one domain isn't a
    -- workload; it's malware shopping for its handler.
    SELECT array_join(slice(split(rtrim(query_name, '.'), '.'), -2, 2), '.') AS parent_domain,
           COUNT(*)                                                          AS nxdomain_lookups,
           COUNT(DISTINCT query_name)                                        AS distinct_names
    FROM route53_resolver_logs
    WHERE rcode = 'NXDOMAIN'
    GROUP BY array_join(slice(split(rtrim(query_name, '.'), '.'), -2, 2), '.')
    ORDER BY nxdomain_lookups DESC
    LIMIT 20;
  SQL
}

resource "aws_athena_named_query" "instance_dns_timeline" {
  name        = "s03-03-instance-dns-timeline"
  description = "DNS lookups from the compromised box over time - line this up with the hunter's SNS alert."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- Pivot from the box (srcids.instance) to what it looked up, when. The mix
    -- of TXT tunnelling and NXDOMAIN beacons unfolds against one instance.
    SELECT from_iso8601_timestamp(query_timestamp) AS query_time,
           query_name,
           query_type,
           rcode
    FROM route53_resolver_logs
    WHERE srcids.instance = '${aws_instance.workload.id}'
    ORDER BY query_time;
  SQL
}
