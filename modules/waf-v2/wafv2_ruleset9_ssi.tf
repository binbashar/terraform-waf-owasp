## 9.
## OWASP Top 10 A9
## Server-side includes & libraries in webroot
## Matches request patterns for webroot objects that shouldn't be directly accessible

resource "aws_wafv2_rule_group" "detect_ssi" {
  name        = "${var.waf_prefix}-detect-ssi"
  description = "Rule group for detecting Server Side Includes - SSI"
  scope       = var.scope
  capacity    = var.capacity

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-detect-ssi"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "match-ssi"
    priority = 1

    statement {
      or_statement {
        statement {
            byte_match_statement {
              search_string = ".cfg"
              field_to_match {
                uri_path {}
              }
              text_transformation {
                priority = 0
                type     = "LOWERCASE"
              }
              positional_constraint = "ENDS_WITH"
            }
          }

          statement {
            byte_match_statement {
              search_string = ".backup"
              field_to_match {
                uri_path {}
              }
              text_transformation {
                priority = 0
                type     = "LOWERCASE"
              }
              positional_constraint = "ENDS_WITH"
            }
          }

          statement {
            byte_match_statement {
              search_string = ".ini"
              field_to_match {
                uri_path {}
              }
              text_transformation {
                priority = 0
                type     = "LOWERCASE"
              }
              positional_constraint = "ENDS_WITH"
            }
          }
          
          statement {
            byte_match_statement {
              search_string = ".conf"
              field_to_match {
                uri_path {}
              }
              text_transformation {
                priority = 0
                type     = "LOWERCASE"
              }
              positional_constraint = "ENDS_WITH"
            }
          }
          
          statement {
            byte_match_statement {
              search_string = ".log"
              field_to_match {
                uri_path {}
              }
              text_transformation {
                priority = 0
                type     = "LOWERCASE"
              }
              positional_constraint = "ENDS_WITH"
            }
          }
          
          statement {
            byte_match_statement {
              search_string = ".bak"
              field_to_match {
                uri_path {}
              }
              text_transformation {
                priority = 0
                type     = "LOWERCASE"
              }
              positional_constraint = "ENDS_WITH"
            }
          }
          
          statement {
            byte_match_statement {
              search_string = ".config"
              field_to_match {
                uri_path {}
              }
              text_transformation {
                priority = 0
                type     = "LOWERCASE"
              }
              positional_constraint = "ENDS_WITH"
            }
          }

          statement {
            byte_match_statement {
              search_string = "/includes"
              field_to_match {
                uri_path {}
              }
              text_transformation {
                priority = 0
                type     = "URL_DECODE"
              }
              positional_constraint = "STARTS_WITH"
            }
          }
        
      }
    }

    action {
      block {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.waf_prefix}-match-ssi"
      sampled_requests_enabled   = true
    }
  }
}

resource "aws_wafv2_web_acl" "detect_ssi" {
  name        = "${var.waf_prefix}-web-acl-detect-sso"
  description = "Web ACL with rule group for detecting SSI"
  scope       = var.scope

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-web-acl-detect-sso"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "detect-ssi-rule-group"
    priority = 1

    statement {
      rule_group_reference_statement {
        arn = aws_wafv2_rule_group.detect_ssi.arn
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
      metric_name                = "${var.waf_prefix}-detect-ssi-rule-group"
      sampled_requests_enabled   = true
    }
  }
}
