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

variable "cloudtrail_log_group_arn" {
  type = string
}

variable "cloudtrail_log_group_name" {
  type = string
}

variable "log_bucket_id" {
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
