## 1.
## OWASP Top 10 A1
## Mitigate SQL Injection Attacks
## Matches attempted SQLi patterns in the URI, QUERY_STRING, BODY, COOKIES

resource "aws_wafv2_rule_group" "mitigate_sqli" {
  name     = "${var.waf_prefix}-generic-mitigate-sqli"
  description = "Rule group to detect SQL Injections"
  capacity = var.capacity
  scope    = var.scope

  rule {
    name     = "sql-injection-match-body"
    priority = 1

    action {
      block {}
    }

    statement {
      sqli_match_statement {
        field_to_match {
          body {}
        }
        text_transformation {
          priority = 1
          type     = "HTML_ENTITY_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "URL_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "${var.waf_prefix}-generic-mitigatesqli-body"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "sql-injection-match-uri"
    priority = 5

    action {
      block {}
    }

    statement {
      sqli_match_statement {
        field_to_match {
          uri_path {}
        }
        text_transformation {
          priority = 1
          type     = "HTML_ENTITY_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "URL_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "${var.waf_prefix}-generic-mitigatesqli-uri"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "sql-injection-match-query-string"
    priority = 10

    action {
      block {}
    }

    statement {
      sqli_match_statement {
        field_to_match {
          query_string {}
        }
        text_transformation {
          priority = 1
          type     = "HTML_ENTITY_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "URL_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "${var.waf_prefix}-generic-mitigatesqli-query-string"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "sql-injection-match-headers"
    priority = 15

    action {
      block {}
    }
    statement {
      sqli_match_statement {
        field_to_match {
          headers {
            match_scope = "ALL"
            oversize_handling = "CONTINUE"

            match_pattern {
              included_headers = [ "Authorization", "cookie" ]
            }
          }
        }

        text_transformation {
          priority = 1
          type     = "HTML_ENTITY_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "URL_DECODE"
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "${var.waf_prefix}-generic-mitigatesqli-headers"
      sampled_requests_enabled   = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "${var.waf_prefix}-generic-mitigatesqli"
    sampled_requests_enabled   = false
  }
}

resource "aws_wafv2_web_acl" "mitigate_sqli" {
  name        = "${var.waf_prefix}-web-acl-mitigate-sqli"
  description = "Web ACL with rule group for SQL Injection Attacks"
  scope       = var.scope

  default_action {
    allow {}
  }

  rule {
    name     = "mitigate-sqli-rule-group"
    priority = 1

    dynamic "override_action" {
      for_each = var.rule_sqli_action == "COUNT" ? [""] : []

      content {
        count {}
      }
    }

    statement {
      rule_group_reference_statement {
        arn     = aws_wafv2_rule_group.mitigate_sqli.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "${var.waf_prefix}-mitigate-sqli-rule-group"
      sampled_requests_enabled   = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "${var.waf_prefix}-web-acl-mitigate-sqli"
    sampled_requests_enabled   = false
  }
}