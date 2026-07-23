variable "name_prefix" {
  description = "Prefix applied to every named resource."
  type        = string
}

variable "auto_fire" {
  description = "Invoke the attack Lambda automatically on apply."
  type        = bool
  default     = true
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "log_bucket_id" {
  type = string
}

# Needed (in addition to log_bucket_id) only for symmetry with the other
# scenarios; the ALB access_logs block addresses the bucket by name.
variable "log_bucket_arn" {
  type = string
}

variable "glue_database_name" {
  type = string
}

variable "athena_workgroup_name" {
  type = string
}

variable "sns_topic_arn" {
  type = string
}

# --- demo signal tuning ------------------------------------------------------

variable "waf_rate_limit" {
  description = "Requests from a single IP over a trailing 5-minute window before the WAF rate-based rule starts blocking. 100 is the WAFv2 minimum; keep it low so the attack's burst trips it."
  type        = number
  default     = 100
}

variable "blocked_requests_threshold" {
  description = "Alarm when this many WAF-blocked requests are seen in a 5-min window. Default 10 - comfortably below the attack's blocked-request volume (the SQLi wave alone is dozens), so the alarm is unambiguous."
  type        = number
  default     = 10
}

variable "sqli_count" {
  description = "Number of SQL-injection-shaped requests the attack Lambda sends (each should be BLOCKed by the SQLi managed rule)."
  type        = number
  default     = 30
}

variable "scan_count" {
  description = "Number of scanning rounds over the scan_paths list (each round hits every path once)."
  type        = number
  default     = 25
}

variable "burst_count" {
  description = "Number of rapid requests to '/' the attack Lambda sends to trip the rate-based rule."
  type        = number
  default     = 150
}

variable "scan_paths" {
  description = "Comma-separated list of sensitive-looking paths the attack Lambda probes (they aren't '/', so the ALB returns 404 unless a managed rule blocks first)."
  type        = string
  default     = "/admin,/.git/config,/wp-login.php,/.env,/phpmyadmin,/api/v1/users,/config.json,/backup.zip,/.aws/credentials,/actuator/env"
}
