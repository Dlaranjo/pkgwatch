"""
Tests for centralized retry logic.
"""

import asyncio
import pytest

from functions.shared.retry import (
    RetryConfig,
    calculate_delay,
    retry_async,
    retry,
)


def test_calculate_delay_exponential():
    """Delay should increase exponentially."""
    config = RetryConfig(base_delay=1.0, exponential_base=2.0, jitter_factor=0.0)

    delay0 = calculate_delay(0, config)
    delay1 = calculate_delay(1, config)
    delay2 = calculate_delay(2, config)

    # Should be exponential: 1, 2, 4
    assert delay0 == pytest.approx(1.0)
    assert delay1 == pytest.approx(2.0)
    assert delay2 == pytest.approx(4.0)


def test_calculate_delay_respects_max():
    """Delay should not exceed max_delay."""
    config = RetryConfig(base_delay=1.0, max_delay=5.0, jitter_factor=0.0)

    delay10 = calculate_delay(10, config)  # Would be 1024 without max

    # Should be capped at max_delay (5.0 + jitter)
    assert delay10 <= 5.0


def test_calculate_delay_adds_jitter():
    """Delay should include jitter to prevent thundering herd."""
    config = RetryConfig(base_delay=1.0, jitter_factor=0.3)

    delays = [calculate_delay(0, config) for _ in range(100)]

    # All delays should be different (due to jitter)
    assert len(set(delays)) > 1

    # All delays should be within expected range (1.0 to 1.3)
    assert all(1.0 <= d <= 1.3 for d in delays)


@pytest.mark.asyncio
async def test_retry_async_success_on_first_attempt():
    """Should return immediately on first success."""
    call_count = 0

    async def test_func():
        nonlocal call_count
        call_count += 1
        return "success"

    config = RetryConfig(max_retries=3)
    result = await retry_async(test_func, config=config)

    assert result == "success"
    assert call_count == 1


@pytest.mark.asyncio
async def test_retry_async_success_after_retries():
    """Should retry until success."""
    call_count = 0

    async def test_func():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise ValueError("temporary error")
        return "success"

    config = RetryConfig(max_retries=3, base_delay=0.01)  # Fast retries for testing
    result = await retry_async(test_func, config=config)

    assert result == "success"
    assert call_count == 3


@pytest.mark.asyncio
async def test_retry_async_exhausts_retries():
    """Should raise last exception after exhausting retries."""
    call_count = 0

    async def test_func():
        nonlocal call_count
        call_count += 1
        raise ValueError("persistent error")

    config = RetryConfig(max_retries=3, base_delay=0.01)

    with pytest.raises(ValueError, match="persistent error"):
        await retry_async(test_func, config=config)

    # Should try: initial + 3 retries = 4 total
    assert call_count == 4


@pytest.mark.asyncio
async def test_retry_async_only_retries_specified_exceptions():
    """Should only retry specified exception types."""
    call_count = 0

    async def test_func():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ValueError("retryable")
        raise TypeError("not retryable")

    config = RetryConfig(
        max_retries=3,
        base_delay=0.01,
        retryable_exceptions=(ValueError,),
    )

    with pytest.raises(TypeError, match="not retryable"):
        await retry_async(test_func, config=config)

    # Should try once, fail with ValueError, retry, then fail with TypeError
    assert call_count == 2


@pytest.mark.asyncio
async def test_retry_decorator():
    """Retry decorator should work correctly."""
    call_count = 0

    @retry(RetryConfig(max_retries=2, base_delay=0.01))
    async def test_func():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise ValueError("temporary")
        return "success"

    result = await test_func()

    assert result == "success"
    assert call_count == 2


@pytest.mark.asyncio
async def test_retry_decorator_with_args():
    """Retry decorator should preserve function arguments."""
    @retry(RetryConfig(max_retries=1, base_delay=0.01))
    async def test_func(a, b, c=None):
        return f"{a}-{b}-{c}"

    result = await test_func("x", "y", c="z")

    assert result == "x-y-z"


@pytest.mark.asyncio
async def test_retry_with_default_config():
    """Should use default config when none provided."""
    call_count = 0

    async def test_func():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise ValueError("temporary")
        return "success"

    # No config provided - should use defaults
    result = await retry_async(test_func)

    assert result == "success"
    assert call_count == 2


@pytest.mark.asyncio
async def test_retry_timing():
    """Verify retry delays are applied."""
    import time

    call_times = []

    async def test_func():
        call_times.append(time.time())
        if len(call_times) < 3:
            raise ValueError("temporary")
        return "success"

    config = RetryConfig(max_retries=3, base_delay=0.1, jitter_factor=0.0)
    await retry_async(test_func, config=config)

    # Verify delays between attempts
    # Attempt 1 -> Attempt 2: ~0.1s delay
    # Attempt 2 -> Attempt 3: ~0.2s delay
    assert len(call_times) == 3

    delay1 = call_times[1] - call_times[0]
    delay2 = call_times[2] - call_times[1]

    assert 0.05 < delay1 < 0.15  # ~0.1s with tolerance
    assert 0.15 < delay2 < 0.25  # ~0.2s with tolerance


@pytest.mark.asyncio
async def test_retry_async_with_kwargs():
    """Retry should work with functions that use kwargs."""
    @retry(RetryConfig(max_retries=1, base_delay=0.01))
    async def test_func(*, value):
        return value * 2

    result = await test_func(value=5)
    assert result == 10
