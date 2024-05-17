## 7.
## OWASP Top 10 A7
## Mitigate abnormal requests via size restrictions
## Enforce consistent request hygene, limit size of key elements

resource "aws_wafv2_rule_group" "size_restrictions" {
  name        = "${var.waf_prefix}-size-restrictions"
  description = "Rule group for restricting sizes"
  scope       = var.scope
  capacity    = var.capacity

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-size-restrictions"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "restrict-cookie-size"
    priority = 1

    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = 4093
        field_to_match {
          single_header {
            name = "cookie"
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
      metric_name                = "${var.waf_prefix}-restrict-cookie-size"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "restrict-query-string-size"
    priority = 2

    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = 1024
        field_to_match {
          query_string {}
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
      metric_name                = "${var.waf_prefix}-restrict-query-string-size"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "restrict-uri-size"
    priority = 3

    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = 512
        field_to_match {
          uri_path {}
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
      metric_name                = "${var.waf_prefix}-restrict-uri-size"
      sampled_requests_enabled   = true
    }
  }
}

resource "aws_wafv2_web_acl" "size_restrictions" {
  name        = "${var.waf_prefix}-web-acl-size-restrictions"
  description = "Web ACL with rule group for size restrictions"
  scope       = var.scope

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-web-acl-size-restrictions"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "size_restrictions_rule_group"
    priority = 1

    statement {
      rule_group_reference_statement {
        arn = aws_wafv2_rule_group.size_restrictions.arn
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
      metric_name                = "${var.waf_prefix}-size-restrictions-rule-group"
      sampled_requests_enabled   = true
    }
  }
}
