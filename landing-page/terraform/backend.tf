terraform {
  backend "s3" {
    bucket         = "pkgwatch-terraform-state"
    key            = "landing-page/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "pkgwatch-terraform-locks" # State locking to prevent concurrent modifications
  }
}

# Note: The DynamoDB table for state locking must be created before using this backend.
# Create it manually with:
#   aws dynamodb create-table \
#     --table-name pkgwatch-terraform-locks \
#     --attribute-definitions AttributeName=LockID,AttributeType=S \
#     --key-schema AttributeName=LockID,KeyType=HASH \
#     --billing-mode PAY_PER_REQUEST \
#     --region us-east-1
