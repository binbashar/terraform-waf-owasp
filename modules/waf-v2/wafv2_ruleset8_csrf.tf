## 8.
## OWASP Top 10 A8
## CSRF token enforcement example
## Enforce the presence of CSRF token in request header

resource "aws_wafv2_rule_group" "csrf_enforcement" {
  name        = "${var.waf_prefix}-csrf-enforcement"
  description = "Rule group for enforcing CSRF protection"
  scope       = var.scope
  capacity    = var.capacity

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}csrf_enforcement"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "exclude-csrf-methods"
    priority = 1

    statement {
      or_statement {

        dynamic "statement" {
          for_each = var.rule_csrf_exclude_methods
          
          content {
            byte_match_statement {
              search_string = statement.value
              field_to_match {
                method {}
              }
              text_transformation {
                priority = 0
                type     = "LOWERCASE"
              }
              positional_constraint = "EXACTLY"
            }
          }
        }
      }
    }

    action {
      allow {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.waf_prefix}-exclude-csrf-methods"
      sampled_requests_enabled   = true
    }
  }

  # rule {
  #   name     = "include-csrf-methods"
  #   priority = 2

  #   statement {
  #     or_statement {

  #       dynamic "statement" {
  #         for_each = var.rule_csrf_include_methods
          
  #         content {
  #           byte_match_statement {
  #             search_string = statement.value
  #             field_to_match {
  #               method {}
  #             }
  #             text_transformation {
  #               priority = 0
  #               type     = "LOWERCASE"
  #             }
  #             positional_constraint = "EXACTLY"
  #           }
  #         }
  #       }
  #     }
  #   }

  #   action {
  #     count {}
  #   }

  #   visibility_config {
  #     cloudwatch_metrics_enabled = true
  #     metric_name                = "${var.waf_prefix}-include-csrf-methods"
  #     sampled_requests_enabled   = true
  #   }
  # }

  rule {
    name     = "csrf-token-size"
    priority = 3

    statement {
      size_constraint_statement {
        comparison_operator = "EQ"
        size                = 36
        field_to_match {
          single_header {
            name = var.rule_csrf_header
          }
        }
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    action {
      block {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.waf_prefix}-csrf-token-size"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "csrf-fetch-same-site"
    priority = 4

    statement {
      byte_match_statement {
        search_string = "same-site"
        field_to_match {
          single_header {
            name = "sec-fetch-site"
          }
        }
        text_transformation {
          priority = 0
          type     = "LOWERCASE"
        }
        positional_constraint = "EXACTLY"
      }
    }

    action {
      block {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.waf_prefix}-csrf-fetch-same-site"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "csrf-fetch-same-origin"
    priority = 5

    statement {
      byte_match_statement {
        search_string = "same-origin"
        field_to_match {
          single_header {
            name = "sec-fetch-site"
          }
        }
        text_transformation {
          priority = 0
          type     = "LOWERCASE"
        }
        positional_constraint = "EXACTLY"
      }
    }

    action {
      block {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.waf_prefix}-csrf-fetch-same-origin"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = var.custom_csrf_token
    content {
      name     = "custom_csrf_token_${each.value.field}"
      priority = 6 + count.index

      statement {
        size_constraint_statement {
          comparison_operator = each.value.operator
          size                = each.value.size
          field_to_match {
            single_header {
              name = each.value.field
            }
          }
          text_transformation {
            priority = 0
            type     = "NONE"
          }
        }
      }

      action {
        block {}
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.waf_prefix}-custom-csrf-token-${each.value.field}"
        sampled_requests_enabled   = true
      }
    }
  }
}

resource "aws_wafv2_web_acl" "csrf_enforcement" {
  name        = "${var.waf_prefix}-web-acl-csrf-enforcement"
  description = "Web ACL with rule group for CSRF enforcement"
  scope       = var.scope

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-web-acl-csrf-enforcement"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "csrf-enforcement-rule-group"
    priority = 1

    statement {
      rule_group_reference_statement {
        arn = aws_wafv2_rule_group.csrf_enforcement.arn
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
      metric_name                = "${var.waf_prefix}-csrf-enforcement-rule-group"
      sampled_requests_enabled   = true
    }
  }
}
