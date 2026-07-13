# The query layer. Scenarios register their Glue tables in this database and ship
# saved queries into this workgroup. Results land in a dedicated prefix so they never
# pollute the AWSLogs/ path the CloudTrail table projects over.

resource "aws_glue_catalog_database" "audit" {
  name = local.glue_db
}

resource "aws_athena_workgroup" "investigations" {
  name          = local.athena_wg
  force_destroy = true

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.logs.id}/${local.athena_prefix}/"
    }
  }
}
