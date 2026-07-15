variable "region" {
  description = "Home region for the trail. Keep us-east-1 so global-service events (IAM, STS) land here."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix applied to every named resource so the whole demo is easy to find and tear down."
  type        = string
  default     = "atkplane"
}

variable "alert_email" {
  description = "Email address subscribed to the SNS alert topic. Leave empty to skip the subscription (you can still see alarms in the console)."
  type        = string
  default     = ""
}

variable "auto_fire" {
  description = "If true, the attack Lambda is invoked automatically on apply. Set false to stand up the estate and fire the attack yourself later."
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "If true, stand up the GuardDuty detector and wire its findings into the detect/respond pipeline (EventBridge -> SNS + quarantine Lambda). GuardDuty is NOT available on the AWS Free Tier, so this defaults to false. When false, the metric-filter alarms still fire off the attack's own CloudTrail signal; only the GuardDuty-driven auto-quarantine is skipped."
  type        = bool
  default     = false
}
