variable "name_prefix" {
  description = "Prefix applied to every named resource."
  type        = string
}

variable "auto_fire" {
  description = "Invoke the attack Lambda automatically on apply."
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Wire GuardDuty findings into the detect/respond pipeline. When false, the egress metric-filter alarm still fires but the GuardDuty EventBridge rule and auto-isolation are skipped."
  type        = bool
  default     = false
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

# Needed (in addition to log_bucket_id) because the S3 flow-log destination is
# addressed by ARN, not name.
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

variable "guardduty_detector_id" {
  type = string
}

# --- demo signal tuning ------------------------------------------------------

variable "egress_bytes_threshold" {
  description = "Alarm when summed egress bytes (ACCEPT, outbound) over a 5-min window cross this. Default 5 MB - comfortably above the otherwise-silent box (SSM heartbeats are KB-scale) and comfortably below the attack's multi-MB upload, so the spike is unambiguous. Raise it if your box has legitimately chatty egress."
  type        = number
  default     = 5000000
}

variable "exfil_endpoint" {
  description = "External URL the on-box attack POSTs its payload to, to generate the egress-bytes signal. Any reachable public endpoint that accepts a POST body works; the attack sends several MB in chunks so even a body-size-capped endpoint still emits enough egress to trip the alarm."
  type        = string
  default     = "https://postman-echo.com/post"
}
