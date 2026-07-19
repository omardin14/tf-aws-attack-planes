# ---------------------------------------------------------------------------
# The optional 'prevent' control. Detection tells you the beacon happened; a
# Route 53 Resolver DNS Firewall rule refuses the lookup outright. This is the
# same detect-versus-prevent split as CloudTrail log-file validation in Part 2:
# the query logs OBSERVE, DNS Firewall PREVENTS.
#
# Everything here is gated on enable_dns_firewall (default false), so the demo is
# detect-only unless you turn it on. Note a BLOCKed lookup is STILL logged (with
# firewall_rule_action = BLOCK), so the hunter and the s03-* queries keep working
# either way - the difference is the query is now refused at the resolver.
# ---------------------------------------------------------------------------

resource "aws_route53_resolver_firewall_domain_list" "blocked" {
  count = var.enable_dns_firewall ? 1 : 0

  name = "${var.name_prefix}-s3-blocked-domains"
  domains = [
    var.beacon_domain,
    "*.${var.beacon_domain}",
    var.tunnel_domain,
    "*.${var.tunnel_domain}",
  ]

  tags = { Name = "${var.name_prefix}-s3-blocked-domains" }
}

resource "aws_route53_resolver_firewall_rule_group" "this" {
  count = var.enable_dns_firewall ? 1 : 0

  name = "${var.name_prefix}-s3-dns-firewall"

  tags = { Name = "${var.name_prefix}-s3-dns-firewall" }
}

resource "aws_route53_resolver_firewall_rule" "block" {
  count = var.enable_dns_firewall ? 1 : 0

  name                    = "${var.name_prefix}-s3-block-c2-and-exfil"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.this[0].id
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.blocked[0].id
  priority                = 100
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
}

resource "aws_route53_resolver_firewall_rule_group_association" "this" {
  count = var.enable_dns_firewall ? 1 : 0

  name                   = "${var.name_prefix}-s3-dns-firewall-assoc"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.this[0].id
  vpc_id                 = aws_vpc.this.id
  priority               = 101
}
