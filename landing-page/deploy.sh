#!/bin/bash
# Deploy landing page to S3 and invalidate CloudFront cache

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEBSITE_DIR="$SCRIPT_DIR/dist"
TERRAFORM_DIR="$SCRIPT_DIR/terraform"
BUCKET_NAME="dephealth-landing-page"
DISTRIBUTION_ID=$(terraform -chdir="$TERRAFORM_DIR" output -raw cloudfront_distribution_id 2>/dev/null || echo "")

echo "=== DepHealth Landing Page Deployment ==="

# Build the Astro site first
echo "Building Astro site..."
cd "$SCRIPT_DIR"
npm run build

# Check if terraform has been applied
if [ -z "$DISTRIBUTION_ID" ]; then
    echo "Error: CloudFront distribution not found. Run 'terraform apply' in terraform/ first."
    exit 1
fi

echo "Uploading to S3 bucket: $BUCKET_NAME"
aws s3 sync "$WEBSITE_DIR" "s3://$BUCKET_NAME" \
    --delete \
    --cache-control "max-age=86400" \
    --exclude ".DS_Store"

echo "Invalidating CloudFront cache..."
aws cloudfront create-invalidation \
    --distribution-id "$DISTRIBUTION_ID" \
    --paths "/*" \
    --output text

echo ""
echo "=== Deployment Complete ==="
echo "Website: https://dephealth.laranjo.dev"
echo ""
