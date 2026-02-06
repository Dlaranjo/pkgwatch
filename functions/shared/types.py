"""
Shared Type Definitions for Lambda Handlers.

Provides TypedDict definitions for AWS Lambda events and responses.
"""

from typing import TypedDict, Optional, Any


class APIGatewayEventHeaders(TypedDict, total=False):
    """Headers from API Gateway event."""

    Authorization: str
    authorization: str
    Host: str
    host: str
    Origin: str
    origin: str


class APIGatewayEvent(TypedDict, total=False):
    """API Gateway proxy event structure."""

    httpMethod: str
    headers: dict[str, str]
    pathParameters: Optional[dict[str, str]]
    queryStringParameters: Optional[dict[str, str]]
    body: Optional[str]
    requestContext: dict[str, Any]
    resource: str
    path: str
    isBase64Encoded: bool


class LambdaContext:
    """Lambda context object (simplified type hints)."""

    function_name: str
    function_version: str
    invoked_function_arn: str
    memory_limit_in_mb: int
    aws_request_id: str
    log_group_name: str
    log_stream_name: str

    def get_remaining_time_in_millis(self) -> int:
        """Get remaining execution time in milliseconds."""
        ...


class LambdaResponse(TypedDict):
    """Standard Lambda response structure."""

    statusCode: int
    headers: dict[str, str]
    body: str


class ErrorBody(TypedDict):
    """Error response body structure."""

    code: str
    message: str


class ErrorResponse(TypedDict):
    """Error wrapper structure."""

    error: ErrorBody


class SQSRecord(TypedDict):
    """SQS record from event."""

    messageId: str
    receiptHandle: str
    body: str
    attributes: dict[str, str]
    messageAttributes: dict[str, Any]
    md5OfBody: str
    eventSource: str
    eventSourceARN: str
    awsRegion: str


class SQSEvent(TypedDict):
    """SQS event structure."""

    Records: list[SQSRecord]


class DynamoDBStreamRecord(TypedDict, total=False):
    """DynamoDB stream record."""

    eventID: str
    eventName: str  # INSERT, MODIFY, REMOVE
    eventVersion: str
    eventSource: str
    awsRegion: str
    dynamodb: dict[str, Any]
    eventSourceARN: str


class DynamoDBStreamEvent(TypedDict):
    """DynamoDB Streams event structure."""

    Records: list[DynamoDBStreamRecord]


class UserInfo(TypedDict, total=False):
    """User information returned from validate_api_key."""

    user_id: str
    key_hash: str
    tier: str
    monthly_limit: int
    requests_this_month: int
    created_at: str
    email: str


class PackageData(TypedDict, total=False):
    """Package data returned from get_package."""

    pk: str
    sk: str
    ecosystem: str
    name: str
    tier: int
    last_updated: str
    health_score: float
    risk_level: str
    score_components: dict[str, Any]
    confidence: dict[str, Any]
    abandonment_risk: dict[str, Any]
    latest_version: str
    weekly_downloads: int
    dependents_count: int
    data_status: str
    queryable: bool
