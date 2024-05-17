## 5.
## OWASP Top 10 A4
## Privileged Module Access Restrictions
## Restrict access to the admin interface to known source IPs only
## Matches the URI prefix, when the remote IP isn't in the whitelist

resource "aws_wafv2_ip_set" "admin_remote_ipset" {
  name        = "${var.waf_prefix}-admin-remote-ipset"
  description = "IP set for admin remote access"
  scope       = var.scope

  ip_address_version = "IPV4"

  addresses = var.admin_remote_ipset
}

resource "aws_wafv2_rule_group" "admin_access_detection" {
  name        = "${var.waf_prefix}-admin-access-detection"
  description = "Rule group for detecting admin access"
  scope       = var.scope
  capacity    = var.capacity

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-admin-access-detection"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "detect-admin-access"
    priority = 1

    statement {
      and_statement {
        
      statement {
        not_statement {
          statement {
            ip_set_reference_statement {
              arn = aws_wafv2_ip_set.admin_remote_ipset.arn
              }
            }
        }
      }

      statement {
        dynamic "byte_match_statement" {
          for_each = var.rule_admin_path_constraints
          content {
            field_to_match {
              uri_path {}
            }
            positional_constraint = byte_match_statement.value.positional_constraint
            search_string         = byte_match_statement.value.target_string
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
              }
            }
          }
        }
      }
    }

    action {
      block {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.waf_prefix}-detect-admin-access"
      sampled_requests_enabled   = true
    }
  }
}

resource "aws_wafv2_web_acl" "admin_access_detection" {
  name        = "${var.waf_prefix}-web-acl-admin-access-detection"
  description = "Web ACL with rule group for admin access detection"
  scope       = "REGIONAL" # or "CLOUDFRONT" for global

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-web-acl-admin-access-detection"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "admin-access-detection-rule-group"
    priority = 1

    statement {
      rule_group_reference_statement {
        arn = aws_wafv2_rule_group.admin_access_detection.arn
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
      metric_name                = "${var.waf_prefix}-admin-access-detection-rule-group"
      sampled_requests_enabled   = true
    }
  }
}
