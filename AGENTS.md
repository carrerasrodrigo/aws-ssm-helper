# Agents Integration Guide

This document provides guidance for AI agents, automation tools, and CI/CD systems on how to effectively work with the AWS SSM Helper project.

## Project Overview

The AWS SSM Helper is a Python library that simplifies retrieval of parameters from AWS Systems Manager Parameter Store. It provides both programmatic access and command-line tools suitable for agent-based automation and Lambda environments.

### Key Features

- **Flexible Encryption**: Support for AWS KMS encryption (recommended for production/Lambda) and local Fernet-based encryption
- **Caching**: Optional caching of parameters with multiple encryption options
- **CLI Tools**: Command-line utilities for shell scripts and automation
- **Lambda-Friendly**: Minimal external dependencies (cryptography is optional)
- **Well-Tested**: 27+ comprehensive tests with full coverage of encryption scenarios

## Project Structure

```
aws-ssm-helper/
├── ssm/                          # Main package
│   ├── __init__.py              # Core library implementation
│   ├── README.md                # Package documentation
│   └── scripts/                 # CLI tools
│       ├── ssm_get_key.py
│       └── ssm_replace_from_input.py
├── tests/                        # Test suite
│   ├── test_client.py           # Main tests (27 tests)
│   └── test_script.py           # CLI tests
├── setup.py                      # Package configuration
├── README.md                     # Project documentation
├── pytest.ini                    # Pytest configuration
├── AGENTS.md                     # This file
└── .pre-commit-config.yaml       # Pre-commit hooks
```

## Agent Workflow

When making changes to this project, follow this workflow:

### 1. Make Code Changes

Edit files as needed:
- Core library changes go in `ssm/__init__.py`
- Tests go in `tests/test_client.py`
- Documentation in `README.md`

### 2. Add/Update Tests

Every feature or bug fix MUST have corresponding tests:

```bash
# Tests should cover:
# - Happy path (feature works as intended)
# - Edge cases (boundary conditions)
# - Error handling (invalid inputs, missing data)
# - Integration (with other features)
```

Example test structure:
```python
def test_new_feature(self):
    """Clear description of what is being tested"""
    # Arrange: Set up test data
    test_data = {"key": "value"}

    # Act: Perform the operation
    result = function_under_test(test_data)

    # Assert: Verify expected outcome
    self.assertEqual(result, expected_value)
```

### 3. Run Pre-Commit Checks

Before committing changes, run pre-commit checks:

```bash
# Run all pre-commit hooks
pre-commit run --all-files

# This will:
# - Check code formatting (Black)
# - Lint Python code (Flake8)
# - Check YAML files
# - Verify file permissions
# - And other configured checks
```

**Important**: If pre-commit makes changes, review them and commit the fixes before running tests.

### 4. Run Tests

After pre-commit passes, run the full test suite:

```bash
# Run all tests with verbose output
pytest tests/ -v

# Run specific test file
pytest tests/test_client.py -v

# Run specific test
pytest tests/test_client.py::TestClient::test_specific_test -v

# Run with coverage report
pytest tests/ --cov=ssm
```

**Expected Result**: All 27+ tests should pass with no linting errors.

### 5. Update Documentation

If adding new features, update `README.md`:

- Add parameter documentation to method descriptions
- Include usage examples (both Python and environment variables)
- Document any new environment variables
- Update the "Cache Encryption" section if relevant
- Include any new dependencies or installation instructions

### 6. Create Commit

After all checks pass:

```bash
git add .
git commit -m "$(cat <<'EOF'
Feature/fix description (1-2 sentences)

- Bullet point 1 explaining what was changed
- Bullet point 2 explaining impact or benefit
EOF
)"
```

## Code Quality Standards

### Python Code Style

- **Line length**: Maximum 120 characters (Flake8 configured)
- **Formatter**: Black (auto-formats code)
- **Linter**: Flake8 (checks for errors and style issues)
- **Type hints**: Recommended but not required

### Test Requirements

- **Minimum coverage**: All public functions must have tests
- **Test naming**: `test_<feature>_<scenario>`
- **Test structure**: Arrange-Act-Assert pattern
- **Mock external services**: Use `unittest.mock` for AWS API calls

### Documentation Requirements

- **Docstrings**: All functions should have docstrings
- **README updates**: Any new features must be documented
- **Examples**: Include both Python and CLI examples
- **Environment variables**: Document all new env vars

## Making Changes: Example Workflow

### Example: Adding KMS Support

```bash
# 1. Make code changes
# Edit ssm/__init__.py to add KMS functions

# 2. Add comprehensive tests
# Edit tests/test_client.py with 5-10 new test cases

# 3. Run pre-commit
pre-commit run --all-files
# Fix any formatting/linting issues that are reported

# 4. Run tests
pytest tests/ -v
# Ensure all tests pass

# 5. Update documentation
# Edit README.md to add:
# - New parameter descriptions
# - KMS usage examples
# - New environment variables (AWS_SSM_ENCRYPTION_KMS_KEY, etc.)

```

## Encryption Features

### Current Implementation

The project supports three encryption modes:

1. **AWS KMS** (Recommended for production/Lambda)
   - No external dependencies needed
   - Uses boto3 (already required)
   - Environment variable: `AWS_SSM_ENCRYPTION_KMS_KEY`
   - Region variable: `AWS_SSM_ENCRYPTION_KMS_REGION`

2. **Local Fernet** (Recommended for development)
   - Requires optional `cryptography` dependency
   - Environment variable: `AWS_SSM_ENCRYPTION_KEY`

3. **No encryption** (Default)
   - Cache stored as plain JSON
   - Good for non-sensitive parameters

### KMS Parameters

When working with KMS, understand these parameters:

- `kms_key_id`: KMS key ID or ARN (required when using KMS)
- `kms_region_name`: AWS region for KMS (optional, defaults to `region_name`)
- `region_name`: AWS region for SSM (also used as fallback for KMS region)

Example in `get_keys()`:
```python
get_keys(
    region_name='us-east-1',          # SSM region
    kms_key_id='arn:aws:kms:...',     # KMS key
    kms_region_name='eu-west-1'       # Optional: Different KMS region
)
```

## Testing Guide

### Test Categories

1. **Unit Tests** - Test individual functions
2. **Integration Tests** - Test functions working together
3. **Error Handling Tests** - Test error conditions and edge cases
4. **Mock Tests** - Test with mocked AWS services

### Common Test Patterns

**Testing with mocked KMS:**
```python
def test_kms_feature(self):
    kms_client = MagicMock()
    kms_client.encrypt.return_value = {"CiphertextBlob": b"encrypted_data"}

    with patch("ssm._get_kms_client", return_value=kms_client):
        result = _encrypt_with_kms(data, key_id, region)
        kms_client.encrypt.assert_called_once()
```

**Testing error handling:**
```python
def test_missing_region_error(self):
    with self.assertRaises(ValueError) as context:
        _encrypt_data(data, kms_key_id="key", region_name=None)
    self.assertIn("KMS region is not provided", str(context.exception))
```

**Testing cache operations:**
```python
def test_cache_creation(self):
    # Create cache
    _build_cache_data(".cache", data, encryption_key="secret")
    self.assertTrue(os.path.exists(".cache"))

    # Verify cache permissions
    self.assertEqual(oct(os.stat(".cache").st_mode), "0o100600")

    # Clean up
    os.remove(".cache")
```

## Environment Variables

### Required by Library

- `AWS_SSM_REGION_NAME`: AWS region
- `AWS_SSM_APP_PATH`: SSM parameter path

### Optional for Encryption

- `AWS_SSM_ENCRYPTION_KMS_KEY`: KMS key ID/ARN (uses KMS if set)
- `AWS_SSM_ENCRYPTION_KMS_REGION`: Region for KMS (defaults to AWS_SSM_REGION_NAME)
- `AWS_SSM_ENCRYPTION_KEY`: Local encryption key (for Fernet encryption)

### Optional for Behavior

- `AWS_SSM_CACHE_FILE`: Cache file path (default: `/tmp/keys.enc`)
- `AWS_SSM_IGNORE_LOAD`: Skip cache loading
- `AWS_SSM_WITH_DECRYPTION`: Decrypt SSM SecureString parameters
- `AWS_SSM_FAIL_ON_ERROR`: Raise errors instead of returning empty dict

## Common Agent Tasks

### Adding a New Function

```python
# 1. Add to ssm/__init__.py
def new_function(param1, param2):
    """Clear docstring"""
    pass

# 2. Add test to tests/test_client.py
def test_new_function(self):
    """Test the new function"""
    pass

# 3. Run checks
pre-commit run --all-files
pytest tests/ -v

# 4. Update README.md if needed
```

### Fixing a Bug

```python
# 1. Write a failing test that reproduces the bug
def test_bug_reproduction(self):
    # This test should fail initially
    pass

# 2. Fix the code in ssm/__init__.py

# 3. Run pre-commit and tests
pre-commit run --all-files
pytest tests/ -v

# 4. Verify the test now passes
```

### Updating Documentation

When updating README.md:
- Keep examples working (test them manually if needed)
- Update parameter tables when adding new options
- Include both Python and CLI examples
- Document new environment variables
- Add to appropriate section (Methods, Installation, Features, etc.)

## Troubleshooting

### Tests Fail After Code Changes

1. Run pre-commit first: `pre-commit run --all-files`
2. Check for missing imports: `from ssm import new_function`
3. Verify test imports are updated
4. Run specific failing test for details: `pytest tests/test_client.py::TestClient::test_name -v`

### Pre-Commit Fails

1. Review the error message carefully
2. Most formatting issues auto-fix on re-run: `pre-commit run --all-files`
3. For persistent issues, check Black and Flake8 configuration
4. Manually fix linting errors if needed

### Import Errors in Tests

- Always import new functions in `tests/test_client.py`
- Use: `from ssm import function_name`
- Check that function is exported in `ssm/__init__.py`

## Quality Assurance Checklist

Before considering a feature complete:

- [ ] Code changes made to `ssm/__init__.py`
- [ ] Tests added/updated in `tests/test_client.py` (all scenarios covered)
- [ ] Pre-commit checks pass: `pre-commit run --all-files`
- [ ] All tests pass: `pytest tests/ -v`
- [ ] README.md updated with new features/parameters
- [ ] New environment variables documented
- [ ] Examples provided (Python and/or CLI)
- [ ] Docstrings updated/added
- [ ] No linting errors: `pytest tests/` shows clean output
- [ ] Manual testing done if applicable

## Performance Considerations

- **Caching**: Enable caching for frequently accessed parameters
- **KMS vs Local Encryption**: KMS is slower but more secure; use KMS for production
- **AWS API Calls**: Minimize by using cache and batching requests
- **Region Usage**: Keep SSM and KMS in same region when possible to reduce latency

## Security Best Practices

1. **Always use KMS in production**: More secure than local encryption
2. **Never commit secrets**: Use environment variables
3. **Set cache file permissions**: Library automatically sets to 0o600
4. **Rotate encryption keys**: Periodically update KMS keys
5. **Use IAM roles**: In Lambda, rely on IAM roles instead of credentials
6. **Validate input**: Check that users provide required parameters

## CI/CD Integration

This project is designed to work with CI/CD systems:

```yaml
# Example GitHub Actions
- name: Pre-commit checks
  run: pre-commit run --all-files

- name: Run tests
  run: pytest tests/ -v

- name: Check coverage
  run: pytest tests/ --cov=ssm
```

## Resources

- [AWS SSM Parameter Store Documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html)
- [AWS KMS Documentation](https://docs.aws.amazon.com/kms/)
- [Pytest Documentation](https://docs.pytest.org/)
- [Black Code Formatter](https://github.com/psf/black)
- [Flake8 Linter](https://flake8.pycqa.org/)

## Contributing

When contributing new features:

1. Follow this workflow: Code → Tests → Pre-commit → Pytest → Docs → Commit
2. Ensure all 27+ tests pass
3. No pre-commit or linting errors
4. Update documentation
5. Write clear commit messages

This ensures the project maintains high code quality and consistency.
