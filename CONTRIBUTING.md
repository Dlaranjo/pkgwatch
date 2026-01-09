# Contributing to DepHealth

Thank you for your interest in contributing to DepHealth!

## Development Setup

### Prerequisites

- Node.js 18+
- Python 3.12+
- AWS CLI configured (for integration tests)
- Git

### Clone and Install

```bash
# Clone the repository
git clone https://github.com/dephealth/dephealth.git
cd dephealth

# Install Node.js dependencies
npm install

# Install Python dependencies
cd functions
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Running Tests

```bash
# Python tests
cd functions
pytest tests/ -v

# CLI tests
cd cli
npm test

# Action tests
cd action
npm test

# Infrastructure tests
cd infrastructure
npm test
```

## Code Style

### Python

- Follow PEP 8
- Use type hints for function signatures
- Maximum line length: 100 characters
- Use docstrings for public functions

```python
def calculate_score(data: dict, weights: dict = None) -> float:
    """
    Calculate health score from package data.

    Args:
        data: Package metrics dictionary
        weights: Optional custom weights

    Returns:
        Health score from 0 to 100
    """
    ...
```

### TypeScript

- Use strict mode
- Prefer `const` over `let`
- Use explicit return types for public functions

```typescript
function formatScore(score: number): string {
  return score.toFixed(1);
}
```

## Pull Request Process

1. **Fork** the repository
2. **Create a branch** for your feature: `git checkout -b feature/my-feature`
3. **Make your changes** with clear, focused commits
4. **Write/update tests** for your changes
5. **Ensure all tests pass**: `npm test` and `pytest`
6. **Submit a pull request** with a clear description

### PR Title Format

Use conventional commits:
- `feat: Add new scoring signal for PR velocity`
- `fix: Handle timeout in GitHub collector`
- `docs: Update API documentation`
- `refactor: Extract shared retry logic`
- `test: Add integration tests for auth flow`

### PR Description Template

```markdown
## Summary
Brief description of changes

## Changes
- Change 1
- Change 2

## Testing
How was this tested?

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
```

## Commit Messages

Follow conventional commits:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Example:
```
feat(scoring): Add issue response time signal

Adds a new signal to the community health component that measures
average time to first response on issues.

Closes #123
```

## Issue Reporting

### Bug Reports

Include:
- Steps to reproduce
- Expected vs actual behavior
- Environment (OS, Node version, Python version)
- Error messages/logs

### Feature Requests

Include:
- Use case description
- Proposed solution
- Alternatives considered

## Code Review

All submissions require review. We use GitHub pull requests for this.

Reviewers will check:
- Code quality and style
- Test coverage
- Documentation
- Performance implications
- Security considerations

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
