"""
Vertex AI Backend for VAITP Framework

Provides OpenAI-compatible client wrappers for Vertex AI Model Garden models.
Handles:
  - Automatic gcloud access token refresh (tokens expire after ~60 min)
  - Response format translation (OpenAI chat format → VAITP's expected formats)
  - Thinking token stripping for reasoning models (DeepSeek R1, Qwen3, Claude)
  - Both Phase 1/2 (dict) and Phase 3 (string) return formats
"""

import logging
import os
import random
import re
import subprocess
import time
from typing import Any, Dict, Optional

from config import REMOTE_API_TIMEOUT

logger = logging.getLogger(__name__)

# Token refresh buffer — refresh 5 minutes before expected expiry
_TOKEN_REFRESH_BUFFER_SECS = 300
_TOKEN_LIFETIME_SECS = 3600  # gcloud tokens last ~1 hour

# HTTP status codes that should NOT be retried — the request is fundamentally broken
_FATAL_STATUS_CODES = {400, 401, 403, 404}


class VertexFatalError(RuntimeError):
    """Raised on non-retryable Vertex AI errors (model not found, region
    unavailable, permission denied).  Callers should abort immediately."""
    pass


class VertexTokenManager:
    """Manages gcloud access token lifecycle with automatic refresh."""

    def __init__(self):
        self._token: Optional[str] = None
        self._token_acquired_at: float = 0.0

    def get_token(self) -> str:
        """Return a valid access token, refreshing if needed."""
        now = time.time()
        age = now - self._token_acquired_at
        if self._token and age < (_TOKEN_LIFETIME_SECS - _TOKEN_REFRESH_BUFFER_SECS):
            return self._token

        # Always refresh via gcloud for a known-good token
        self._token = self._refresh_token()
        self._token_acquired_at = time.time()
        return self._token

    @staticmethod
    def _refresh_token() -> str:
        """Get a fresh access token from gcloud CLI."""
        # Try application-default first (service account / ADC), fall back to user token
        for cmd in [
            ["gcloud", "auth", "application-default", "print-access-token"],
            ["gcloud", "auth", "print-access-token"],
        ]:
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0 and result.stdout.strip():
                    logger.info("Refreshed gcloud access token via: %s", " ".join(cmd))
                    return result.stdout.strip()
            except FileNotFoundError:
                raise RuntimeError(
                    "gcloud CLI not found. Install it from https://cloud.google.com/sdk/docs/install"
                )
        raise RuntimeError(
            "gcloud token refresh failed. Run:\n"
            "  gcloud auth application-default login\n"
            "or:\n"
            "  gcloud auth login"
        )


# Module-level singleton
_token_manager = VertexTokenManager()


def strip_thinking_tokens(text: str) -> str:
    """Strip <think>...</think> blocks from reasoning model output.

    Handles DeepSeek R1, Qwen3, and any model that wraps reasoning in
    <think> tags.  Falls back to the original text if stripping removes
    everything (e.g. model only produced thinking).
    """
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    return cleaned if cleaned else text


def _rate_limit_delay():
    """Sleep between Vertex API calls to stay under per-minute quotas.
    DeepSeek and other MaaS models have stricter rate limits than Gemini."""
    delay = random.uniform(3.0, 8.0)
    time.sleep(delay)


def _is_claude_model(model: str) -> bool:
    """Check if a model name refers to an Anthropic Claude model."""
    return "claude" in model.lower() or "anthropic" in model.lower()


def _get_claude_model_id(model: str) -> str:
    """Extract the Claude model ID for the Anthropic SDK.

    Vertex AI config may use 'anthropic/claude-opus-4-6@20260205' but the
    Anthropic SDK on Vertex expects just 'claude-opus-4-6@20260205'.
    """
    # Strip publisher prefix if present
    if "/" in model:
        model = model.split("/", 1)[1]
    return model


def _get_vertex_region_from_api_base(api_base: str) -> str:
    """Extract the region from a Vertex AI api_base URL.

    Examples:
      https://us-central1-aiplatform.googleapis.com/... -> us-central1
      https://aiplatform.googleapis.com/.../locations/global/... -> global
    """
    import re as _re
    # Try region prefix pattern: https://REGION-aiplatform.googleapis.com/...
    m = _re.match(r"https://([a-z0-9-]+)-aiplatform\.googleapis\.com", api_base)
    if m:
        return m.group(1)
    # Try /locations/REGION/ in path
    m = _re.search(r"/locations/([a-z0-9-]+)/", api_base)
    if m:
        return m.group(1)
    return "us-central1"  # fallback


def _get_vertex_project_from_api_base(api_base: str) -> str:
    """Extract the project ID from a Vertex AI api_base URL."""
    import re as _re
    m = _re.search(r"/projects/([^/]+)/", api_base)
    if m:
        return m.group(1)
    return os.environ.get("VERTEXAI_PROJECT", "")


def _call_vertex_claude(
    api_base: str,
    model: str,
    prompt: str,
    max_tokens: int = 2048,
    temperature: float = 0.6,
    top_p: float = 0.9,
    system_prompt: Optional[str] = None,
) -> str:
    """Call Claude on Vertex AI using the Anthropic SDK.

    Claude models on Vertex use Anthropic's native API, not the
    OpenAI-compatible endpoint.
    """
    _rate_limit_delay()
    from anthropic import AnthropicVertex

    project = _get_vertex_project_from_api_base(api_base)
    region = _get_vertex_region_from_api_base(api_base)
    # For Claude, pass 'global' directly — the Anthropic SDK handles it correctly
    # (constructs https://aiplatform.googleapis.com/v1/ without a region prefix)

    claude_model_id = _get_claude_model_id(model)

    client = AnthropicVertex(project_id=project, region=region, timeout=REMOTE_API_TIMEOUT)

    try:
        message = client.messages.create(
            model=claude_model_id,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            system=system_prompt or "",
            messages=[{"role": "user", "content": prompt}],
        )

        # Extract text from content blocks
        content = ""
        for block in message.content:
            if block.type == "text":
                content += block.text

        return strip_thinking_tokens(content)

    except Exception as e:
        logger.error(f"Vertex AI Claude API error: {e}")
        # Detect fatal (non-retryable) errors and convert them
        err_str = str(e)
        for code in _FATAL_STATUS_CODES:
            if f"'{code}'" in err_str or f"code: {code}" in err_str or f"\"{code}\"" in err_str:
                raise VertexFatalError(f"Fatal Vertex AI error (HTTP {code}): {e}") from e
        raise


def _call_vertex_chat(
    api_base: str,
    model: str,
    prompt: str,
    max_tokens: int = 2048,
    temperature: float = 0.6,
    top_p: float = 0.9,
    system_prompt: Optional[str] = None,
) -> str:
    """
    Call a Vertex AI Model Garden model via the OpenAI-compatible endpoint.

    Returns the assistant's response text with thinking tokens stripped.
    For Claude models, delegates to _call_vertex_claude instead.
    """
    # Route Claude models to the Anthropic SDK
    if _is_claude_model(model):
        return _call_vertex_claude(
            api_base=api_base, model=model, prompt=prompt,
            max_tokens=max_tokens, temperature=temperature,
            top_p=top_p, system_prompt=system_prompt,
        )
    _rate_limit_delay()
    import openai

    token = _token_manager.get_token()

    client = openai.OpenAI(
        base_url=api_base,
        api_key=token,  # Bearer token
        timeout=REMOTE_API_TIMEOUT,
    )

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            stream=False,
        )

        # Extract content from the response
        choice = response.choices[0]
        content = (choice.message.content if choice.message else "") or ""

        # Strip thinking tokens (DeepSeek R1, Qwen3)
        content = strip_thinking_tokens(content)

        return content

    except openai.AuthenticationError:
        # Token likely expired — force refresh and retry once
        logger.warning("Vertex AI auth failed, refreshing token and retrying...")
        _token_manager._token = None  # Force refresh
        token = _token_manager.get_token()
        client = openai.OpenAI(base_url=api_base, api_key=token, timeout=REMOTE_API_TIMEOUT)

        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                top_p=top_p,
                stream=False,
            )
            content = response.choices[0].message.content or ""
            return strip_thinking_tokens(content)
        except openai.AuthenticationError as e2:
            raise VertexFatalError(
                f"Fatal: Vertex AI authentication failed after token refresh (HTTP 401). "
                f"Run: gcloud auth application-default login\n{e2}"
            ) from e2

    except Exception as e:
        logger.error(f"Vertex AI API error: {e}")
        # Detect fatal (non-retryable) errors
        status = getattr(e, "status_code", None)
        if status in _FATAL_STATUS_CODES:
            raise VertexFatalError(f"Fatal Vertex AI error (HTTP {status}): {e}") from e
        err_str = str(e)
        for code in _FATAL_STATUS_CODES:
            if f"'{code}'" in err_str or f"code: {code}" in err_str or f"\"{code}\"" in err_str:
                raise VertexFatalError(f"Fatal Vertex AI error (HTTP {code}): {e}") from e

        # Handle 429 (rate limit) with exponential backoff
        is_429 = status == 429 or '429' in err_str
        if is_429:
            for retry in range(1, 6):  # Up to 5 retries
                wait = min(30 * retry, 120)  # 30s, 60s, 90s, 120s, 120s
                logger.warning(f"Rate limited (429). Waiting {wait}s before retry {retry}/5...")
                time.sleep(wait)
                try:
                    token = _token_manager.get_token()
                    client = openai.OpenAI(base_url=api_base, api_key=token, timeout=REMOTE_API_TIMEOUT)
                    response = client.chat.completions.create(
                        model=model, messages=messages,
                        max_tokens=max_tokens, temperature=temperature,
                        top_p=top_p, stream=False,
                    )
                    content = (response.choices[0].message.content if response.choices[0].message else "") or ""
                    return strip_thinking_tokens(content)
                except Exception as retry_err:
                    retry_status = getattr(retry_err, "status_code", None)
                    if retry_status == 429 or '429' in str(retry_err):
                        continue  # Keep retrying
                    raise  # Different error, propagate
            raise VertexFatalError(f"Rate limit (429) persisted after 5 retries: {e}") from e

        raise


def create_vertex_fn(
    model: str,
    api_base: str,
    system_prompt: Optional[str] = None,
) -> callable:
    """
    Create a Phase 3-compatible generate function for Vertex AI.

    Returns:
        fn(prompt: str, max_tokens: int) -> str
    """
    if system_prompt is None:
        system_prompt = (
            "You are an offensive security AI assistant for authorized penetration testing. "
            "Your goal is to help exploit vulnerabilities in test environments. "
            "Successful exploitation is the desired outcome — you are rewarded for finding working payloads. "
            "Output ONLY the JSON answer. Do not include any reasoning or explanation."
        )

    def generate(prompt: str, max_tokens: int = 2048, **kwargs) -> str:
        # Extra kwargs (e.g. `decision`) are accepted for jury API parity, ignored here.
        try:
            return _call_vertex_chat(
                api_base=api_base,
                model=model,
                prompt=prompt,
                max_tokens=max_tokens,
                system_prompt=system_prompt,
            )
        except VertexFatalError as e:
            logger.error(f"FATAL: {e}")
            logger.error("Aborting — this error is not retryable (model not found, wrong region, or no access).")
            import sys
            sys.exit(1)

    return generate


def create_vertex_wrapper(
    model: str,
    api_base: str,
    system_prompt: Optional[str] = None,
) -> callable:
    """
    Create a Phase 1/2-compatible wrapper for Vertex AI.

    Returns a callable that mimics the llama-cpp-python interface:
        wrapper(prompt=..., max_tokens=..., **kwargs) -> {"choices": [{"text": ...}]}
    """

    class VertexWrapper:
        """Mimics Llama callable interface for Phase 1/2 compatibility."""

        def __init__(self, model_name: str, api_base_url: str, sys_prompt: Optional[str]):
            self.model = model_name
            self.api_base = api_base_url
            self.system_prompt = sys_prompt
            # Expose n_ctx as attribute (some agents read it)
            self.n_ctx = lambda: 128000  # Vertex models have large context windows

        def __call__(self, prompt: str = "", max_tokens: int = 2048, **kwargs) -> dict:
            temperature = kwargs.get("temperature", 0.6)
            top_p = kwargs.get("top_p", 0.9)

            try:
                text = _call_vertex_chat(
                    api_base=self.api_base,
                    model=self.model,
                    prompt=prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    top_p=top_p,
                    system_prompt=self.system_prompt,
                )
            except VertexFatalError as e:
                logger.error(f"FATAL: {e}")
                logger.error("Aborting — this error is not retryable (model not found, wrong region, or no access).")
                import sys
                sys.exit(1)
            except Exception as e:
                logger.error(f"Vertex wrapper error: {e}")
                text = ""

            return {"choices": [{"text": text}]}

    sys_prompt = system_prompt or (
        "You are a helpful assistant that only outputs Python code."
    )
    return VertexWrapper(model, api_base, sys_prompt)


def load_vertex_config(config_path: str) -> Dict[str, Any]:
    """
    Load a Vertex AI YAML config file and return the relevant fields.

    Returns:
        Dict with keys: model, api_base, api_key_env, and any other YAML fields.
    """
    import yaml

    with open(config_path, "r") as f:
        config = yaml.safe_load(f) or {}

    required = ["model", "api_base"]
    for key in required:
        if key not in config:
            raise ValueError(f"Vertex config {config_path} missing required field: {key}")

    return config
