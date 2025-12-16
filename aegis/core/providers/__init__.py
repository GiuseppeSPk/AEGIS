"""LLM Providers module."""

from aegis.core.providers.base import BaseLLMProvider, LLMResponse
from aegis.core.providers.factory import (
    create_judge_provider,
    create_provider,
    list_available_providers,
)
from aegis.core.providers.ollama import OllamaProvider
from aegis.core.providers.openai import OpenAIProvider


# Lazy imports for optional providers (require API keys)
def get_anthropic_provider():
    from aegis.core.providers.anthropic import AnthropicProvider

    return AnthropicProvider


def get_google_provider():
    from aegis.core.providers.google import GoogleProvider

    return GoogleProvider


__all__ = [
    "BaseLLMProvider",
    "LLMResponse",
    "OllamaProvider",
    "OpenAIProvider",
    "create_provider",
    "create_judge_provider",
    "list_available_providers",
    "get_anthropic_provider",
    "get_google_provider",
]
