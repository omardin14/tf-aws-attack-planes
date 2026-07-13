# ---------------------------------------------------------------------------
# The investigation layer. A Glue table over the CloudTrail logs (partition
# projection, so no crawler / MSCK REPAIR) plus the saved queries the blog walks
# through. Open the Athena workgroup and run them to "pull the thread".
# ---------------------------------------------------------------------------

locals {
  cloudtrail_location = "s3://${var.log_bucket_id}/AWSLogs/${var.account_id}/CloudTrail"
  # Regions the multi-region trail may write. Projection enumerates them so no
  # partition load is ever needed.
  projection_regions = join(",", [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "sa-east-1", "ca-central-1",
  ])

  # CloudTrail record schema (see AWS "Querying CloudTrail logs" docs).
  cloudtrail_columns = [
    { name = "eventversion", type = "string" },
    { name = "useridentity", type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>" },
    { name = "eventtime", type = "string" },
    { name = "eventsource", type = "string" },
    { name = "eventname", type = "string" },
    { name = "awsregion", type = "string" },
    { name = "sourceipaddress", type = "string" },
    { name = "useragent", type = "string" },
    { name = "errorcode", type = "string" },
    { name = "errormessage", type = "string" },
    { name = "requestparameters", type = "string" },
    { name = "responseelements", type = "string" },
    { name = "additionaleventdata", type = "string" },
    { name = "requestid", type = "string" },
    { name = "eventid", type = "string" },
    { name = "resources", type = "array<struct<arn:string,accountid:string,type:string>>" },
    { name = "eventtype", type = "string" },
    { name = "apiversion", type = "string" },
    { name = "readonly", type = "string" },
    { name = "recipientaccountid", type = "string" },
    { name = "serviceeventdetails", type = "string" },
    { name = "sharedeventid", type = "string" },
    { name = "vpcendpointid", type = "string" },
    { name = "eventcategory", type = "string" },
  ]
}

resource "aws_glue_catalog_table" "cloudtrail" {
  name          = "cloudtrail_logs"
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
    "projection.enabled"            = "true"
    "projection.region.type"        = "enum"
    "projection.region.values"      = local.projection_regions
    "projection.date.type"          = "date"
    "projection.date.range"         = "2024/01/01,NOW"
    "projection.date.format"        = "yyyy/MM/dd"
    "projection.date.interval"      = "1"
    "projection.date.interval.unit" = "DAYS"
    "storage.location.template"     = "${local.cloudtrail_location}/$${region}/$${date}"
  }

  storage_descriptor {
    location      = local.cloudtrail_location
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "com.amazon.emr.hive.serde.CloudTrailSerde"
    }

    dynamic "columns" {
      for_each = local.cloudtrail_columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
  }
}

# --- Saved investigation queries (created, not executed) ---------------------

resource "aws_athena_named_query" "user_timeline" {
  name        = "s01-01-what-is-this-user-doing"
  description = "The whole timeline for the leaked principal - the canonical control-plane query."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- What is this user doing? Read the shape of the output: a burst of Describe*/List*
    -- with errors is enumeration; then the errors stop and the calls narrow.
    SELECT eventtime, eventsource, eventname, sourceipaddress, useragent, errorcode
    FROM cloudtrail_logs
    WHERE useridentity.username = '${local.leaked_user_name}'
    ORDER BY eventtime;
  SQL
}

resource "aws_athena_named_query" "enumeration" {
  name        = "s01-02-enumeration-error-rate"
  description = "Denied calls grouped by source IP - the enumeration burst made legible."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- A high error rate from one source is someone poking at the edges of what a key can do.
    SELECT sourceipaddress, errorcode, count(*) AS calls
    FROM cloudtrail_logs
    WHERE useridentity.username = '${local.leaked_user_name}'
      AND errorcode IS NOT NULL
    GROUP BY sourceipaddress, errorcode
    ORDER BY calls DESC;
  SQL
}

resource "aws_athena_named_query" "persistence" {
  name        = "s01-03-persistence-actions"
  description = "New users, keys, policy attachments and trust edits - the shape of persistence."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- The escalation/persistence moment: what identities did they mint or empower?
    SELECT eventtime, useridentity.username AS actor, eventname, sourceipaddress,
           json_extract_scalar(requestparameters, '$.userName') AS target_user
    FROM cloudtrail_logs
    WHERE eventname IN ('CreateUser','CreateAccessKey','AttachUserPolicy',
                        'PutUserPolicy','UpdateAssumeRolePolicy')
    ORDER BY eventtime;
  SQL
}

resource "aws_athena_named_query" "top_talkers" {
  name        = "s01-04-source-ips-and-agents"
  description = "Where did the principal call from, and with what tooling?"
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- sourceIPAddress + userAgent for the principal: a suspiciously generic SDK
    -- string from an IP you don't operate in is the tell.
    SELECT sourceipaddress, useragent, count(*) AS calls
    FROM cloudtrail_logs
    WHERE useridentity.username = '${local.leaked_user_name}'
    GROUP BY sourceipaddress, useragent
    ORDER BY calls DESC;
  SQL
}
