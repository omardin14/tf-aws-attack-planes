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
  description = "Wire GuardDuty findings into the detect pipeline. When false, the scheduled DNS hunter is the whole detection story; the GuardDuty EventBridge rule is skipped."
  type        = bool
  default     = false
}

variable "enable_dns_firewall" {
  description = "Stand up a Route 53 Resolver DNS Firewall rule group that BLOCKs the demo beacon/tunnel domains - the 'prevent' half of the detect-vs-prevent split. Off by default so the demo is detect-only; a blocked lookup is still logged, so the hunter/queries keep working."
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

# Needed (in addition to log_bucket_id) because the Resolver query-log S3
# destination is addressed by ARN, not name.
variable "log_bucket_arn" {
  type = string
}

variable "glue_database_name" {
  type = string
}

variable "athena_workgroup_name" {
  type = string
}

# Where the hunter Lambda tells Athena to write query results. Comes from the
# foundation (its Athena workgroup already enforces this same location).
variable "athena_results_location" {
  type = string
}

variable "sns_topic_arn" {
  type = string
}

variable "guardduty_detector_id" {
  type = string
}

# --- demo signal tuning ------------------------------------------------------

variable "beacon_domain" {
  description = "Parent domain the DGA beacon appends its pseudo-random labels to. Nothing needs to resolve - the point is a storm of NXDOMAIN lookups to nonsense names. Keep it a domain you don't control so the labels genuinely NXDOMAIN."
  type        = string
  default     = "dga-c2-demo.example"
}

variable "tunnel_domain" {
  description = "Parent domain the DNS-tunnelling exfil queries its long, high-entropy first labels against. Stands in for an attacker-controlled zone."
  type        = string
  default     = "exfil.attacker-demo.example"
}

variable "window_minutes" {
  description = "How far back each scheduled hunter run looks in the Resolver query logs. Should comfortably exceed the hunter's schedule interval + Resolver-log delivery lag so no window is missed."
  type        = number
  default     = 15
}

variable "tunnel_label_len" {
  description = "First-label length (chars) at or above which the hunter flags a name as DNS tunnelling. Normal DNS labels are short; tunnelling packs data into long labels. Also drives the length of the labels the attack emits."
  type        = number
  default     = 30
}

variable "nxdomain_threshold" {
  description = "Number of NXDOMAIN responses to one parent domain, within the window, at or above which the hunter flags a DGA beacon."
  type        = number
  default     = 30
}
