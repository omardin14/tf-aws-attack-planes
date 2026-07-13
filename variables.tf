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
