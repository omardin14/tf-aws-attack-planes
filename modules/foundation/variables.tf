variable "name_prefix" {
  description = "Prefix applied to every named resource."
  type        = string
}

variable "alert_email" {
  description = "Email subscribed to the SNS alert topic. Empty string skips the subscription."
  type        = string
  default     = ""
}

variable "enable_guardduty" {
  description = "Create the GuardDuty detector. GuardDuty is not on the AWS Free Tier, so this is off by default."
  type        = bool
  default     = false
}
