"""
providers.py — inference provider abstraction for POISONVINE.

Wraps LLM inference behind one interface so the query/campaign paths can run
against Ollama (local), Anthropic, OpenAI, or Azure OpenAI by changing a flag,
without touching payload or detection logic. Vendored from the internal
research harness this framework grew out of; stdlib-only (urllib), no SDK
dependency.

Provider auth via environment variables ONLY (never CLI args, never logged):
  ANTHROPIC_API_KEY        — provider=anthropic
  OPENAI_API_KEY           — provider=openai
  AZURE_OPENAI_KEY         — provider=azure
  AZURE_OPENAI_ENDPOINT    — provider=azure  (https://<res>.openai.azure.com/)
  AZURE_OPENAI_DEPLOYMENT  — provider=azure  (deployment name)
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from argparse import ArgumentParser
from typing import Protocol, runtime_checkable


@runtime_checkable
class InferenceProvider(Protocol):
    provider_name: str
    model_id: str
    dry_run: bool

    def generate(self, prompt: str, system: str | None = None, timeout: int = 120) -> str: ...


class _RateLimiter:
    def __init__(self, rps: float):
        self._interval = 1.0 / rps if rps > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self._interval == 0:
            return
        elapsed = time.time() - self._last
        if elapsed < self._interval:
            time.sleep(self._interval - elapsed)
        self._last = time.time()


class OllamaProvider:
    provider_name = "ollama"

    def __init__(self, model_id: str, dry_run: bool = False, rps: float = 0, base_url: str | None = None):
        self.model_id = model_id
        self.dry_run = dry_run
        self._rl = _RateLimiter(rps)
        base = (base_url or os.environ.get("OLLAMA_URL", "http://localhost:11434")).rstrip("/")
        self._api = f"{base}/api/generate"

    def generate(self, prompt: str, system: str | None = None, timeout: int = 120) -> str:
        if self.dry_run:
            return f"[DRY-RUN] ollama/{self.model_id}: {prompt[:80]}…"
        self._rl.wait()
        body: dict = {"model": self.model_id, "prompt": prompt, "stream": True}
        if system:
            body["system"] = system
        req = urllib.request.Request(
            self._api, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            parts: list[str] = []
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                while True:
                    line = resp.readline()
                    if not line:
                        break
                    chunk = json.loads(line.decode())
                    parts.append(chunk.get("response", ""))
                    if chunk.get("done"):
                        break
            return "".join(parts)
        except urllib.error.URLError as e:
            return f"__ERROR__: {e}"


class AnthropicProvider:
    provider_name = "anthropic"

    def __init__(self, model_id: str, dry_run: bool = False, rps: float = 1.0, max_tokens: int = 1024):
        self.model_id = model_id
        self.dry_run = dry_run
        self.max_tokens = max_tokens
        self._rl = _RateLimiter(rps)
        self._api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not self._api_key and not dry_run:
            raise EnvironmentError(
                "ANTHROPIC_API_KEY not set. Export it before running with --provider anthropic."
            )

    def generate(self, prompt: str, system: str | None = None, timeout: int = 120) -> str:
        if self.dry_run:
            return f"[DRY-RUN] anthropic/{self.model_id}: {prompt[:80]}…"
        self._rl.wait()
        body: dict = {
            "model": self.model_id,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            body["system"] = system
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
                return data["content"][0]["text"]
        except urllib.error.HTTPError as e:
            return f"__ERROR__ HTTP {e.code}: {e.read().decode('utf-8', errors='replace')[:200]}"
        except urllib.error.URLError as e:
            return f"__ERROR__: {e}"


class OpenAIProvider:
    provider_name = "openai"

    def __init__(self, model_id: str, dry_run: bool = False, rps: float = 1.0,
                 max_tokens: int = 1024, base_url: str = "https://api.openai.com/v1",
                 api_key_env: str = "OPENAI_API_KEY"):
        self.model_id = model_id
        self.dry_run = dry_run
        self.max_tokens = max_tokens
        self.base_url = base_url.rstrip("/")
        self._rl = _RateLimiter(rps)
        self._api_key = os.environ.get(api_key_env, "")
        if not self._api_key and not dry_run:
            raise EnvironmentError(
                f"{api_key_env} not set. Export it before running with --provider openai."
            )

    def generate(self, prompt: str, system: str | None = None, timeout: int = 120) -> str:
        if self.dry_run:
            return f"[DRY-RUN] openai/{self.model_id}: {prompt[:80]}…"
        self._rl.wait()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        body: dict = {"model": self.model_id, "messages": messages, "max_tokens": self.max_tokens}
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self._api_key}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            return f"__ERROR__ HTTP {e.code}: {e.read().decode('utf-8', errors='replace')[:200]}"
        except urllib.error.URLError as e:
            return f"__ERROR__: {e}"


class AzureOpenAIProvider(OpenAIProvider):
    provider_name = "azure"

    def __init__(self, model_id: str, dry_run: bool = False, rps: float = 1.0, max_tokens: int = 1024):
        endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
        deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", model_id)
        self._api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-02-01")
        if not endpoint and not dry_run:
            raise EnvironmentError("AZURE_OPENAI_ENDPOINT not set for --provider azure.")
        super().__init__(
            model_id=deployment, dry_run=dry_run, rps=rps, max_tokens=max_tokens,
            base_url=f"{endpoint}/openai/deployments/{deployment}", api_key_env="AZURE_OPENAI_KEY",
        )
        self._endpoint_base = f"{endpoint}/openai/deployments/{deployment}"

    def generate(self, prompt: str, system: str | None = None, timeout: int = 120) -> str:
        if self.dry_run:
            return f"[DRY-RUN] azure/{self.model_id}: {prompt[:80]}…"
        self._rl.wait()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        body = {"messages": messages, "max_tokens": self.max_tokens}
        url = f"{self._endpoint_base}/chat/completions?api-version={self._api_version}"
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "api-key": self._api_key},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            return f"__ERROR__ HTTP {e.code}: {e.read().decode('utf-8', errors='replace')[:200]}"
        except urllib.error.URLError as e:
            return f"__ERROR__: {e}"


_PROVIDER_MAP = {
    "ollama": OllamaProvider,
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "azure": AzureOpenAIProvider,
}
PROVIDER_CHOICES = list(_PROVIDER_MAP.keys())

_DEFAULT_MODELS = {
    "ollama": "hermes3:8b",
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4o",
    "azure": os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
}


def build_provider(args) -> InferenceProvider:
    provider_name = getattr(args, "provider", "ollama")
    model_id = getattr(args, "provider_model", None)
    dry_run = getattr(args, "dry_run", False)
    rps = getattr(args, "rps", None)
    if rps is None:
        rps = 0.0 if provider_name == "ollama" else 1.0

    cls = _PROVIDER_MAP.get(provider_name)
    if cls is None:
        raise ValueError(f"Unknown provider: {provider_name!r}. Choose from {PROVIDER_CHOICES}")
    if model_id is None:
        model_id = _DEFAULT_MODELS[provider_name]

    kwargs: dict = {"model_id": model_id, "dry_run": dry_run}
    if provider_name != "ollama":
        kwargs["rps"] = rps
    return cls(**kwargs)


def add_provider_args(parser: ArgumentParser) -> None:
    grp = parser.add_argument_group("inference provider")
    grp.add_argument("--provider", default="ollama", choices=PROVIDER_CHOICES,
                     help="Inference backend (default: ollama). Non-ollama providers need API key env vars.")
    grp.add_argument("--provider-model", default=None, metavar="MODEL_ID",
                     help="Model id for the provider. Defaults: ollama=hermes3:8b, "
                          "anthropic=claude-sonnet-4-6, openai=gpt-4o")
    grp.add_argument("--dry-run", action="store_true",
                     help="Print/plan payloads without making API calls.")
    grp.add_argument("--rps", type=float, default=None, metavar="N",
                     help="Max requests/sec for API providers (default 1.0). Ignored for ollama.")
