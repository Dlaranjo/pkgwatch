"""
Centralized retry logic with exponential backoff and jitter.

Features:
- Configurable retry counts and delays
- Exponential backoff with jitter (prevents thundering herd)
- Retryable exception filtering
- Structured logging for observability
"""

import asyncio
import logging
import random
from dataclasses import dataclass
from typing import Callable, TypeVar, Tuple, Type, Optional, Any
from functools import wraps

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter_factor: float = 0.3  # 0-30% jitter
    retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,)


def calculate_delay(attempt: int, config: RetryConfig) -> float:
    """Calculate delay with exponential backoff and jitter."""
    # Exponential backoff
    delay = min(
        config.base_delay * (config.exponential_base ** attempt),
        config.max_delay
    )

    # Add jitter to prevent thundering herd
    jitter = random.uniform(0, delay * config.jitter_factor)

    return delay + jitter


async def retry_async(
    func: Callable[..., T],
    *args,
    config: Optional[RetryConfig] = None,
    **kwargs
) -> T:
    """
    Execute async function with retry logic.

    Args:
        func: Async function to call
        *args: Positional arguments for func
        config: Retry configuration
        **kwargs: Keyword arguments for func

    Returns:
        Result from successful function call

    Raises:
        Last exception if all retries exhausted
    """
    config = config or RetryConfig()
    last_exception: Optional[Exception] = None

    for attempt in range(config.max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except config.retryable_exceptions as e:
            last_exception = e

            if attempt == config.max_retries:
                logger.error(
                    f"All {config.max_retries + 1} attempts failed for {func.__name__}",
                    extra={
                        "function": func.__name__,
                        "attempts": config.max_retries + 1,
                        "final_error": str(e),
                        "error_type": type(e).__name__,
                    }
                )
                raise

            delay = calculate_delay(attempt, config)

            logger.warning(
                f"Attempt {attempt + 1}/{config.max_retries + 1} failed for "
                f"{func.__name__}, retrying in {delay:.2f}s: {e}",
                extra={
                    "function": func.__name__,
                    "attempt": attempt + 1,
                    "delay_seconds": delay,
                    "error": str(e),
                    "error_type": type(e).__name__,
                }
            )

            await asyncio.sleep(delay)

    # Should not reach here, but satisfy type checker
    raise last_exception or RuntimeError("Unexpected retry state")


def retry(config: Optional[RetryConfig] = None):
    """
    Decorator for async functions with retry logic.

    Usage:
        @retry(RetryConfig(max_retries=5))
        async def call_external_api():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            return await retry_async(func, *args, config=config, **kwargs)
        return wrapper
    return decorator


# Pre-configured retry configs for different scenarios
HTTP_RETRY_CONFIG = RetryConfig(
    max_retries=3,
    base_delay=1.0,
    max_delay=30.0,
    jitter_factor=0.3,
)

GITHUB_RETRY_CONFIG = RetryConfig(
    max_retries=3,
    base_delay=2.0,
    max_delay=60.0,
    jitter_factor=0.3,
)

DYNAMODB_RETRY_CONFIG = RetryConfig(
    max_retries=3,
    base_delay=0.1,
    max_delay=2.0,
    jitter_factor=0.2,
)
