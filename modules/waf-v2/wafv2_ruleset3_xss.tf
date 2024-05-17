## 3.
## OWASP Top 10 A3
## Mitigate Cross Site Scripting Attacks
## Matches attempted XSS patterns in the URI, QUERY_STRING, BODY, COOKIES

resource "aws_wafv2_rule_group" "mitigate_xss" {
  name        = "${var.waf_prefix}-generic-mitigate-xss"
  description = "Rule group to mitigate XSS attacks"
  scope       = "REGIONAL"
  capacity    = var.capacity

  rule {
    name     = "mitigate-xss"
    priority = 1

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          xss_match_statement {
            field_to_match {
              body {}
            }
            text_transformation {
              priority = 1
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              body {}
            }
            text_transformation {
              priority = 2
              type     = "URL_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 1
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 2
              type     = "URL_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 1
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 2
              type     = "URL_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              single_header {
                name = "cookie"
              }
            }
            text_transformation {
              priority = 1
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              single_header {
                name = "cookie"
              }
            }
            text_transformation {
              priority = 2
              type     = "URL_DECODE"
            }
          }
        }

      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.waf_prefix}-generic-mitigate-xss"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-generic-mitigate-xss"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl" "mitigate_xss" {
  name        = "${var.waf_prefix}-web-acl-mitigate-xss"
  description = "Web ACL with rule group for Cross Site Scripting Attacks"
  scope       = var.scope

  default_action {
    allow {}
  }

  rule {
    name     = "mitigate-xss-rule-group"

    priority = 1

    dynamic "override_action" {
      for_each = var.rule_sqli_action == "COUNT" ? [""] : []

      content {
        count {}
      }
    }

    statement {
      rule_group_reference_statement {
        arn = aws_wafv2_rule_group.mitigate_xss.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.waf_prefix}-mitigate-xss-rule-group"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-web-acl-mitigate-xss"
    sampled_requests_enabled   = true
  }
}
