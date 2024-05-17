## 4.
## OWASP Top 10 A4
## Path Traversal, LFI, RFI
## Matches request patterns designed to traverse filesystem paths, and include
## local or remote files

resource "aws_wafv2_rule_group" "rfi_lfi_traversal" {
  name        = "${var.waf_prefix}-rfi-lfi-traversal"
  description = "Rule group for detecting RFI, LFI, and path traversal attacks"
  scope       = var.scope
  capacity = var.capacity

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-rfi-lfi-traversal"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "detect-rfi-lfi-traversal"
    priority = 1

    statement {
      or_statement {
        statement {
          byte_match_statement {
            search_string           = "://"
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 0
              type     = "HTML_ENTITY_DECODE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        statement {
          byte_match_statement {
            search_string           = "../"
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 0
              type     = "HTML_ENTITY_DECODE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        statement {
          byte_match_statement {
            search_string           = "://"
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        statement {
          byte_match_statement {
            search_string           = "../"
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        statement {
          byte_match_statement {
            search_string           = "://"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "HTML_ENTITY_DECODE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        statement {
          byte_match_statement {
            search_string           = "../"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "HTML_ENTITY_DECODE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        statement {
          byte_match_statement {
            search_string           = "://"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        statement {
          byte_match_statement {
            search_string           = "../"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            positional_constraint = "CONTAINS"
          }
        }
      }
    }

    action {
      block {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.waf_prefix}-detect-rfi-lfi-traversal"
      sampled_requests_enabled   = true
    }
  }
}

resource "aws_wafv2_web_acl" "rfi_lfi_traversal" {
  name        = "${var.waf_prefix}-web-acl-detect-rfi-lfi-traversal"
  description = "Web ACL with rule group for RFI/LFI and path traversal detection"
  scope       = var.scope

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-web-acl-detect-rfi-lfi-traversal"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "detect-rfi-lfi-traversal-rule-group"
    priority = 1

    dynamic "override_action" {
      for_each = var.rule_sqli_action == "COUNT" ? [""] : []

      content {
        count {}
      }
    }

    statement {
      rule_group_reference_statement {
        arn = aws_wafv2_rule_group.rfi_lfi_traversal.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.waf_prefix}-rfi-lfi-traversal-rule-group"
      sampled_requests_enabled   = true
    }
  }
}
