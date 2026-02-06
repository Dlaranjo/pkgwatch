"""
Shared constants for PkgWatch.
"""

# Tier configuration
TIER_LIMITS = {
    "free": 5000,
    "starter": 25000,
    "pro": 100000,
    "business": 500000,
}

TIER_NAMES = list(TIER_LIMITS.keys())

# Tier ordering for upgrade/downgrade validation
TIER_ORDER = {"free": 0, "starter": 1, "pro": 2, "business": 3}

# Rate limiting
MAX_KEYS_PER_USER = 5
DEMO_REQUESTS_PER_HOUR = 20

# API configuration
SUPPORTED_ECOSYSTEMS = ["npm", "pypi"]

# Scoring
RISK_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SCORE_COMPONENTS = [
    "maintainer_health",
    "user_centric",
    "evolution",
    "community",
    "security",
]

# External APIs
DEPSDEV_API = "https://api.deps.dev/v3"
# Dependents endpoint only exists in v3alpha, not in stable v3 API
# See: https://docs.deps.dev/api/v3alpha/ (has GetDependents)
# vs:  https://docs.deps.dev/api/v3/      (no GetDependents)
DEPSDEV_API_ALPHA = "https://api.deps.dev/v3alpha"
NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_API = "https://pypi.org/pypi"
PYPISTATS_API = "https://pypistats.org/api"
GITHUB_API = "https://api.github.com"
BUNDLEPHOBIA_API = "https://bundlephobia.com/api/size"

# Timeouts
DEFAULT_TIMEOUT = 30.0
GITHUB_TIMEOUT = 45.0

# Rate limit shards
RATE_LIMIT_SHARDS = 10
GITHUB_HOURLY_LIMIT = 4000

# DynamoDB throttling error codes that should trigger retry
THROTTLING_ERRORS = (
    "ProvisionedThroughputExceededException",
    "RequestLimitExceeded",
    "ThrottlingException",
    "InternalServerError",
)
