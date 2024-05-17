## 2.
## OWASP Top 10 A2
## Blacklist bad/hijacked JWT tokens or session IDs
## Matches the specific values in the cookie or Authorization header
## for JWT it is sufficient to check the signature

resource "aws_wafv2_rule_group" "detect_bad_auth_tokens" {
  name        = "${var.waf_prefix}-generic-detect-bad-auth-tokens"
  description = "Rule group to detect bad auth tokens"
  capacity    = var.capacity
  scope       = var.scope

  rule {
    name     = "bad-auth-token"
    priority = 1

    action {
      block {}
    }

    statement {

      byte_match_statement {
        search_string = ".TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
        positional_constraint = "ENDS_WITH"

        field_to_match {
          single_header {
            name = "authorization"
          }
        }

        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "${var.waf_prefix}-generic-bad-auth-token"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "bad-auth-cookie"
    priority = 5

    action {
      block {}
    }

    statement {
      byte_match_statement {
        search_string          = "example-session-id"
        field_to_match {
          single_header {
            name = "cookie"
          }
        }
        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
        positional_constraint = "CONTAINS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "${var.waf_prefix}-genericbad-auth-cookie"
      sampled_requests_enabled   = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-generic-bad-auth"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl" "detect_bad_auth_tokens" {
  name        = "${var.waf_prefix}-web-acl-detect-bad-auth-tokens"
  description = "Web ACL with rule group for bad/hijacked JWT tokens or session IDs"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "bad-auth-rule-group"
    priority = 1

    dynamic "override_action" {
      for_each = var.rule_sqli_action == "COUNT" ? [""] : []

      content {
        count {}
      }
    }
    
    statement {
      rule_group_reference_statement {
        arn = aws_wafv2_rule_group.detect_bad_auth_tokens.arn
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.waf_prefix}-bad-auth-rule-group"
      sampled_requests_enabled   = true
    }
  }


  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "${var.waf_prefix}-web-acl-bad-auth"
    sampled_requests_enabled   = false
  }
}