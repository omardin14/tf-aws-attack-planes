provider "aws" {
  region = var.region

  default_tags {
    tags = {
      "atkplane:project" = var.name_prefix
      "atkplane:managed" = "terraform"
    }
  }
}
