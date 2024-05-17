## 10.
## Generic
## IP Blacklist
## Matches IP addresses that should not be allowed to access content

resource "aws_wafv2_ip_set" "blacklisted_ips" {
  name        = "${var.waf_prefix}-blacklisted-ips"
  description = "IP set for blacklisted IPs"
  scope       = var.scope

  ip_address_version = "IPV4"

  addresses = [
    for ip in var.blacklisted_ips : ip
  ]
}

resource "aws_wafv2_rule_group" "detect_blacklisted_ips" {
  name        = "${var.waf_prefix}-detect-blacklisted-ips"
  description = "Rule group for detecting blacklisted IPs"
  scope       = var.scope
  capacity    = var.capacity

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-detect-blacklisted-ips"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "match-blacklisted-ips"
    priority = 1

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blacklisted_ips.arn
      }
    }

    action {
      block {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.waf_prefix}-match-blacklisted-ips"
      sampled_requests_enabled   = true
    }
  }
}

resource "aws_wafv2_web_acl" "detect_blacklisted_ips" {
  name        = "${var.waf_prefix}-web-acl-detect-blacklisted-ips"
  description = "Web ACL with rule group for detecting blacklisted IPs"
  scope       = var.scope

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-web-acl-detect-blacklisted-ips"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "detect_blacklisted_ips_rule_group"
    priority = 1

    statement {
      rule_group_reference_statement {
        arn = aws_wafv2_rule_group.detect_blacklisted_ips.arn
      }
    }

    dynamic "override_action" {
      for_each = var.rule_sqli_action == "COUNT" ? [""] : []

      content {
        count {}
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.waf_prefix}-detect-blacklisted-ips-rule-group"
      sampled_requests_enabled   = true
    }
  }
}
