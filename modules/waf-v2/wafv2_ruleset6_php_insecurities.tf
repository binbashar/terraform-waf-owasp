## 6.
## OWASP Top 10 A5
## PHP Specific Security Misconfigurations
## Matches request patterns designed to exploit insecure PHP/CGI configuration

resource "aws_wafv2_rule_group" "php_insecure_detection" {
  name        = "${var.waf_prefix}-php-insecure-detection"
  description = "Rule group for detecting insecure PHP configurations"
  scope       = var.scope
  capacity    = var.capacity

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}php_insecure_detection"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "detect-php-insecure-uri"
    priority = 1

    statement {
      byte_match_statement {
        search_string           = "php"
        field_to_match {
          uri_path {}
        }
        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }
        positional_constraint = "ENDS_WITH"
      }
    }

    action {
      block {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.waf_prefix}-detect-php-insecure-uri"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "detect-php-insecure-var-refs"
    priority = 2

    statement {
      or_statement {
        statement {
          byte_match_statement {
            search_string           = "_ENV["
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
            search_string           = "auto_append_file="
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
            search_string           = "disable_functions="
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
            search_string           = "auto_prepend_file="
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
            search_string           = "safe_mode="
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
            search_string           = "_SERVER["
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
            search_string           = "allow_url_include="
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
            search_string           = "open_basedir="
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
      }
    }

      action {
        block {}
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.waf_prefix}-detect-php-insecure-var-refs"
        sampled_requests_enabled   = true
      }
    
  }
}

resource "aws_wafv2_web_acl" "php_insecure_detection" {
  name        = "${var.waf_prefix}-web-acl-php-insecure-detection"
  description = "Web ACL with rule group for PHP insecure detection"
  scope       = "REGIONAL" # or "CLOUDFRONT" for global

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.waf_prefix}-web-acl-php-insecure-detection"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "php-insecure-detection-rule-group"
    priority = 1

    statement {
      rule_group_reference_statement {
        arn = aws_wafv2_rule_group.php_insecure_detection.arn
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
      metric_name                = "${var.waf_prefix}-php-insecure-detection-rule-group"
      sampled_requests_enabled   = true
    }
  }
}
