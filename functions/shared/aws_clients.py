"""
Centralized AWS client factory with lazy initialization.

Reduces cold start overhead by deferring boto3 client/resource creation
until first use. All Lambdas share the same pattern.
"""

_dynamodb = None
_sqs = None
_secretsmanager = None
_s3 = None
_sns = None


def get_dynamodb():
    """Get DynamoDB resource, creating it lazily on first use."""
    global _dynamodb
    if _dynamodb is None:
        import boto3
        _dynamodb = boto3.resource("dynamodb")
    return _dynamodb


def get_sqs():
    """Get SQS client, creating it lazily on first use."""
    global _sqs
    if _sqs is None:
        import boto3
        _sqs = boto3.client("sqs")
    return _sqs


def get_secretsmanager():
    """Get Secrets Manager client, creating it lazily on first use."""
    global _secretsmanager
    if _secretsmanager is None:
        import boto3
        _secretsmanager = boto3.client("secretsmanager")
    return _secretsmanager


def get_s3():
    """Get S3 client, creating it lazily on first use."""
    global _s3
    if _s3 is None:
        import boto3
        _s3 = boto3.client("s3")
    return _s3


def get_sns():
    """Get SNS client, creating it lazily on first use."""
    global _sns
    if _sns is None:
        import boto3
        _sns = boto3.client("sns")
    return _sns


def reset_clients():
    """Reset all cached clients. Used in tests for clean state."""
    global _dynamodb, _sqs, _secretsmanager, _s3, _sns
    _dynamodb = None
    _sqs = None
    _secretsmanager = None
    _s3 = None
    _sns = None
