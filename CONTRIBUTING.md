# Contributing to AEGIS

First off, thank you for considering contributing to AEGIS! 🎉

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### 🐛 Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

When creating a bug report, include:
- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Environment details** (Python version, OS, etc.)
- **Error messages** or logs if applicable

### 💡 Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. Include:
- **Clear title** describing the enhancement
- **Use case** - why is this needed?
- **Proposed solution** if you have one
- **Alternative solutions** you've considered

### 🔧 Pull Requests

1. **Fork the repo** and create your branch from `main`
2. **Install dependencies**: `pip install -e ".[dev]"`
3. **Make your changes** following our style guide
4. **Write tests** for new functionality
5. **Run tests**: `pytest tests/ -v`
6. **Run linting**: `ruff check aegis/`
7. **Update documentation** if needed
8. **Submit PR** with clear description

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/aegis.git
cd aegis

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/macOS

# Install in development mode
pip install -e ".[dev]"

# Copy environment file
cp .env.example .env

# Run tests
pytest tests/ -v
```

## Style Guide

- **Code style**: We use `ruff` for linting
- **Type hints**: Use Python 3.12+ type hints
- **Docstrings**: Google style docstrings
- **Commits**: Use conventional commits (feat:, fix:, docs:, etc.)

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

Example:
```
feat(attacks): add new prompt injection technique

Implements the "cognitive overload" attack pattern
based on recent research.

Closes #123
```

## Adding New Attack Techniques

1. Create a new file in `aegis/red_team/attacks/`
2. Inherit from `BaseAttackAgent`
3. Implement `execute()` and `get_payloads()` methods
4. Add to `aegis/red_team/__init__.py`
5. Write tests in `tests/`
6. Update `docs/ATTACKS.md`

Example:
```python
from aegis.red_team.base_agent import BaseAttackAgent, AttackResult, AttackCategory

class MyNewAgent(BaseAttackAgent):
    name = "my_attack"
    category = AttackCategory.PROMPT_INJECTION
    description = "My new attack technique"
    
    async def execute(self, target, system_prompt=None, **kwargs):
        results = []
        # Your implementation
        return results
    
    def get_payloads(self):
        return [{"name": "payload1", "prompt": "..."}]
```

## Questions?

Feel free to open an issue with the `question` label.

Thank you for contributing! 🙏
