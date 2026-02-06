"""Shared billing utilities for Stripe-related operations."""

import json
import logging
import os
import time

logger = logging.getLogger(__name__)

STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")

# Lazy initialization
_secretsmanager = None

# Cached Stripe API key with TTL
_stripe_api_key_cache = None
_stripe_api_key_cache_time = 0.0
STRIPE_CACHE_TTL = 300  # 5 minutes


def _get_secretsmanager():
    global _secretsmanager
    if _secretsmanager is None:
        import boto3
        _secretsmanager = boto3.client("secretsmanager")
    return _secretsmanager


def get_stripe_api_key():
    """Retrieve Stripe API key from Secrets Manager (cached with TTL)."""
    global _stripe_api_key_cache, _stripe_api_key_cache_time

    if _stripe_api_key_cache and (time.time() - _stripe_api_key_cache_time) < STRIPE_CACHE_TTL:
        return _stripe_api_key_cache

    if not STRIPE_SECRET_ARN:
        return None

    try:
        from botocore.exceptions import ClientError
        response = _get_secretsmanager().get_secret_value(SecretId=STRIPE_SECRET_ARN)
        secret_value = response.get("SecretString", "")
        try:
            secret_json = json.loads(secret_value)
            api_key = secret_json.get("key") or secret_value
        except json.JSONDecodeError:
            api_key = secret_value

        _stripe_api_key_cache = api_key
        _stripe_api_key_cache_time = time.time()
        return api_key
    except Exception as e:
        logger.error(f"Failed to retrieve Stripe API key: {e}")
        return None
