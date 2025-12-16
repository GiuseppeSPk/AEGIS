# GitHub Configuration

This directory contains GitHub-specific configuration files.

## Contents

### Issue Templates (`ISSUE_TEMPLATE/`)
- `bug_report.md` - Template for reporting bugs
- `feature_request.md` - Template for suggesting new features

### Pull Requests
- `PULL_REQUEST_TEMPLATE.md` - Template for all pull requests

### Workflows (`workflows/`)
- `ci.yml` - Continuous Integration workflow (tests, linting, build)

## Workflows

### CI Workflow

Triggered on:
- Push to `main` or `develop` branches
- Pull requests to `main`

Jobs:
1. **Test** - Runs pytest, ruff, and mypy
2. **Build** - Builds the Python package

## Adding New Templates

To add a new issue template:
1. Create a new `.md` file in `ISSUE_TEMPLATE/`
2. Use YAML front matter for configuration
3. Include appropriate labels and assignees
