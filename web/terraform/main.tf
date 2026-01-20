# PkgWatch Landing Page Infrastructure
# S3 + CloudFront for static hosting

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ACM Certificate for custom domain
resource "aws_acm_certificate" "landing_page" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  tags = {
    Name    = "PkgWatch Landing Page Certificate"
    Project = "pkgwatch"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"  # Required for CloudFront
}

variable "domain_name" {
  description = "Domain name for the landing page"
  type        = string
  default     = "pkgwatch.dev"
}

variable "bucket_name" {
  description = "S3 bucket name"
  type        = string
  default     = "pkgwatch-landing-page"
}

# S3 Bucket for static website
resource "aws_s3_bucket" "landing_page" {
  bucket = var.bucket_name

  tags = {
    Name        = "PkgWatch Landing Page"
    Environment = "production"
    Project     = "pkgwatch"
  }
}

# Block public access (CloudFront will access via OAC)
resource "aws_s3_bucket_public_access_block" "landing_page" {
  bucket = aws_s3_bucket.landing_page.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 bucket policy for CloudFront access
resource "aws_s3_bucket_policy" "landing_page" {
  bucket = aws_s3_bucket.landing_page.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudFrontAccess"
        Effect    = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.landing_page.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.landing_page.arn
          }
        }
      }
    ]
  })
}

# CloudFront Origin Access Control
resource "aws_cloudfront_origin_access_control" "landing_page" {
  name                              = "pkgwatch-oac"
  description                       = "OAC for PkgWatch landing page"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# CloudFront Function for URL rewrites (handles /docs -> /docs/index.html)
resource "aws_cloudfront_function" "url_rewrite" {
  name    = "pkgwatch-url-rewrite"
  runtime = "cloudfront-js-2.0"
  publish = true
  code    = <<-EOF
    function handler(event) {
      var request = event.request;
      var uri = request.uri;

      // If URI ends with / add index.html
      if (uri.endsWith('/')) {
        request.uri += 'index.html';
      }
      // If URI doesn't have an extension and doesn't end with /, try adding /index.html
      else if (!uri.includes('.')) {
        request.uri += '/index.html';
      }

      return request;
    }
  EOF
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "landing_page" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  comment             = "PkgWatch Landing Page"
  price_class         = "PriceClass_100"  # US, Canada, Europe only (cheapest)

  aliases = [var.domain_name]

  origin {
    domain_name              = aws_s3_bucket.landing_page.bucket_regional_domain_name
    origin_id                = "S3-${var.bucket_name}"
    origin_access_control_id = aws_cloudfront_origin_access_control.landing_page.id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${var.bucket_name}"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 86400    # 1 day
    max_ttl     = 31536000 # 1 year

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.url_rewrite.arn
    }
  }

  # Custom error response for SPA (if needed later)
  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/index.html"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.landing_page.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  tags = {
    Name        = "PkgWatch Landing Page CDN"
    Environment = "production"
    Project     = "pkgwatch"
  }
}

# Outputs
output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = aws_cloudfront_distribution.landing_page.id
}

output "cloudfront_domain_name" {
  description = "CloudFront domain name (use this for Cloudflare CNAME)"
  value       = aws_cloudfront_distribution.landing_page.domain_name
}

output "s3_bucket_name" {
  description = "S3 bucket name for uploading files"
  value       = aws_s3_bucket.landing_page.id
}

output "website_url" {
  description = "Website URL"
  value       = "https://${var.domain_name}"
}

output "certificate_validation_records" {
  description = "DNS records to add to Cloudflare for certificate validation"
  value = {
    for dvo in aws_acm_certificate.landing_page.domain_validation_options : dvo.domain_name => {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  }
}
