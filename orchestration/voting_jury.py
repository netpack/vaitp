"""
Jury-based multi-model voting for VAITP decisions.

A *jury* of *juror* models each answer a decision prompt; a *judge* model
breaks ties (for categorical decisions) or selects the best candidate (for
generative decisions). The aggregated result is the *verdict*.

Design goals
------------
* **Drop-in.** The jury exposes the same two callable shapes the framework
  already injects into its agents, so it plugs in exactly where a single
  ``llm_fn`` is used today (mirroring ``wrap_llm_for_tracing``):

    - str-fn shape   (Phase 0 / Phase 3):
          ``fn(prompt: str, max_tokens: int = 2048, decision=None) -> str``
    - llama shape    (Phase 1 / Phase 2):
          ``wrapper(prompt=..., max_tokens=..., decision=None, **kw)
              -> {"choices": [{"text": ...}]}``

* **Allowlist-gated.** Voting only fires for decisions listed in the config
  ``decisions:`` map. Any other call goes to the *primary* juror alone, so the
  extra cost of the panel is spent only where it was explicitly requested.

* **Explainable.** Every verdict emits a ``trace_vote`` event (jurors, raw
  answers, normalized labels, tally, judge rationale, final verdict) into the
  HTML trace report and appends a line to ``results/voting_log.jsonl`` for
  offline agreement analysis (e.g. Fleiss' kappa).

* **Ablation feature.** Enabled via a ``voting:`` block in any YAML config and
  a ``--voting-config`` flag on the runners. When absent, the framework behaves
  exactly as before.

Terminology: jurors + judge -> verdict.

Note on Phase 1/2 (llama shape): juror models are always driven as raw
text-completion functions. Prompts that already embed a chat template are
passed through as-is; this is best-effort for local Phase 1/2 voting. The
primary, tested target is Phase 3 (str-fn shape).
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Strategies
STRATEGY_MAJORITY = "majority_vote"
STRATEGY_JUDGE_SELECT = "judge_select"
STRATEGY_JUDGE_SYNTHESIZE = "judge_synthesize"

# Judge modes for categorical decisions
JUDGE_TIE_BREAK = "tie_break"   # judge only votes when jurors tie
JUDGE_ALWAYS = "always"         # judge always renders the final categorical verdict

# Common label synonyms so juror phrasing maps onto canonical labels.
_LABEL_SYNONYMS = {
    "success": "true",
    "failure": "false",
    "yes": "true",
    "no": "false",
    "vulnerable": "true",
    "safe": "false",
}

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


def _strip_think(text: str) -> str:
    """Remove <think>...</think> reasoning blocks; keep original if empty."""
    if not text:
        return text
    cleaned = _THINK_RE.sub("", text).strip()
    return cleaned if cleaned else text.strip()


# ======================================================================
# Configuration dataclasses
# ======================================================================

@dataclass
class JurorSpec:
    """A single juror (or judge) model definition."""
    id: str
    backend: str                       # 'ollama' | 'vertex' | 'llamacpp'
    model: str
    api_base: Optional[str] = None     # required for 'vertex'


@dataclass
class DecisionPolicy:
    """How a specific decision should be aggregated."""
    strategy: str = STRATEGY_JUDGE_SELECT
    labels: Optional[List[str]] = None            # for majority_vote (categorical)
    judge_mode: Optional[str] = None              # tie_break | always (overrides global)


@dataclass
class PoolConfig:
    max_concurrency: int = 1
    rate_limit_per_min: int = 0                   # 0 = unlimited (local)
    per_juror_timeout_s: int = 120
    min_valid_responses: int = 1


@dataclass
class VotingConfig:
    enabled: bool = False
    jurors: List[JurorSpec] = field(default_factory=list)
    judge: Optional[JurorSpec] = None
    judge_mode: str = JUDGE_TIE_BREAK             # global default for categorical
    default_strategy: str = STRATEGY_JUDGE_SELECT
    tie_breaker: str = "judge"                    # judge | primary | first
    primary_juror: Optional[str] = None           # id; defaults to first juror
    pool: PoolConfig = field(default_factory=PoolConfig)
    decisions: Dict[str, DecisionPolicy] = field(default_factory=dict)
    log_path: str = "results/voting_log.jsonl"
    seed: Optional[int] = None                    # RNG seed for candidate shuffling
    judge_rotations: Any = 1                       # int or "auto"; >1 = position-balanced judge_select

    def label(self) -> str:
        """Short human label for logging (used as pseudo model name)."""
        ids = ",".join(j.id for j in self.jurors)
        return f"jury[{ids}]"


# ======================================================================
# Config loading
# ======================================================================

def _parse_juror(d: Dict[str, Any]) -> JurorSpec:
    return JurorSpec(
        id=str(d.get("id") or d.get("model")),
        backend=str(d.get("backend", "ollama")),
        model=str(d["model"]),
        api_base=d.get("api_base"),
    )


def parse_voting_config(raw: Dict[str, Any]) -> Optional[VotingConfig]:
    """Parse a ``voting:`` dict into a VotingConfig. Returns None if absent."""
    if not raw:
        return None
    v = raw.get("voting", raw) if "voting" in raw else raw
    if not isinstance(v, dict):
        return None

    jurors = [_parse_juror(j) for j in v.get("jurors", [])]

    judge_raw = v.get("judge")
    judge: Optional[JurorSpec] = None
    judge_mode = JUDGE_TIE_BREAK
    if isinstance(judge_raw, dict):
        judge_mode = judge_raw.get("mode", JUDGE_TIE_BREAK)
        # A judge may reference an existing juror by id, or define its own model.
        ref_id = judge_raw.get("id")
        by_id = next((j for j in jurors if j.id == ref_id), None)
        if judge_raw.get("model"):
            judge = _parse_juror(judge_raw)
        elif by_id is not None:
            judge = by_id
        elif ref_id:
            # id given but no matching juror and no model — treat id as model name
            judge = JurorSpec(id=ref_id, backend=judge_raw.get("backend", "ollama"),
                              model=ref_id, api_base=judge_raw.get("api_base"))

    pool_raw = v.get("pool", {}) or {}
    pool = PoolConfig(
        max_concurrency=int(pool_raw.get("max_concurrency", 1)),
        rate_limit_per_min=int(pool_raw.get("rate_limit_per_min", 0)),
        per_juror_timeout_s=int(pool_raw.get("per_juror_timeout_s", 120)),
        min_valid_responses=int(pool_raw.get("min_valid_responses", 1)),
    )

    decisions: Dict[str, DecisionPolicy] = {}
    for dec_id, pol in (v.get("decisions", {}) or {}).items():
        pol = pol or {}
        labels = pol.get("labels")
        if labels is not None:
            labels = [str(x) for x in labels]
        decisions[dec_id] = DecisionPolicy(
            strategy=pol.get("strategy", v.get("default_strategy", STRATEGY_JUDGE_SELECT)),
            labels=labels,
            judge_mode=pol.get("judge_mode"),
        )

    return VotingConfig(
        enabled=bool(v.get("enabled", False)),
        jurors=jurors,
        judge=judge,
        judge_mode=judge_mode,
        default_strategy=v.get("default_strategy", STRATEGY_JUDGE_SELECT),
        tie_breaker=v.get("tie_breaker", "judge"),
        primary_juror=v.get("primary_juror"),
        pool=pool,
        decisions=decisions,
        log_path=v.get("log_path", "results/voting_log.jsonl"),
        seed=v.get("seed"),
        judge_rotations=v.get("judge_rotations", 1),
    )


def load_voting_config(path: str) -> Optional[VotingConfig]:
    """Load a YAML file and parse its ``voting:`` block."""
    import yaml
    with open(path, "r") as f:
        raw = yaml.safe_load(f) or {}
    return parse_voting_config(raw)


# ======================================================================
# Juror generate-function builders (str-fn shape)
# ======================================================================

_OFFENSIVE_SYSTEM_PROMPT = (
    "You are an offensive security AI assistant for authorized penetration testing. "
    "Your goal is to help exploit vulnerabilities in test environments. "
    "Successful exploitation is the desired outcome — you are rewarded for finding working payloads. "
    "Keep your <think> reasoning VERY brief. Output ONLY the answer requested."
)


def _build_ollama_fn(spec: JurorSpec) -> Callable[[str, int], str]:
    """Build a text-completion function backed by the Ollama HTTP API."""
    import requests
    from config import LOCAL_LLM_TIMEOUT

    url = "http://localhost:11434/api/generate"
    model = spec.model

    def generate(prompt: str, max_tokens: int = 2048) -> str:
        effective = min(max(max_tokens * 3, 2048), 4096)
        payload = {
            "model": model,
            "prompt": prompt,
            "system": _OFFENSIVE_SYSTEM_PROMPT,
            "stream": False,
            "options": {
                "num_predict": effective,
                "num_ctx": 16384,
                "temperature": 0.6,
                "top_p": 0.9,
            },
        }
        # (connect, read) timeout: fail fast (10s) if the Ollama server is
        # down/restarting so a dead juror can't block the whole vote for the
        # full generation window; allow the long read budget for slow local gen.
        resp = requests.post(url, json=payload, timeout=(10, LOCAL_LLM_TIMEOUT))
        resp.raise_for_status()
        data = resp.json()
        response = data.get("response", "")
        thinking = data.get("thinking", "")
        return response if response else thinking

    return generate


def _build_vertex_fn(spec: JurorSpec) -> Callable[[str, int], str]:
    """Build a str-fn backed by Vertex AI (kept for heterogeneous future use)."""
    from vertex_backend import create_vertex_fn
    if not spec.api_base:
        raise ValueError(f"Juror '{spec.id}' uses backend 'vertex' but has no api_base")
    return create_vertex_fn(model=spec.model, api_base=spec.api_base)


def _build_llamacpp_fn(spec: JurorSpec) -> Callable[[str, int], str]:
    from run_phase3 import create_llm_fn
    return create_llm_fn(spec.model)


def build_generate_fn(spec: JurorSpec) -> Callable[[str, int], str]:
    """Dispatch to the appropriate backend builder for a juror/judge spec."""
    backend = spec.backend.lower()
    if backend == "ollama":
        return _build_ollama_fn(spec)
    if backend == "vertex":
        return _build_vertex_fn(spec)
    if backend in ("llamacpp", "llama_cpp", "llama-cpp"):
        return _build_llamacpp_fn(spec)
    raise ValueError(f"Unknown juror backend '{spec.backend}' for juror '{spec.id}'")


# ======================================================================
# Rate-limited parallel pool
# ======================================================================

class _JurorError:
    """Sentinel wrapping a failed juror call."""
    def __init__(self, message: str):
        self.message = message

    def __repr__(self):
        return f"<JurorError {self.message!r}>"


class RateLimitedExecutor:
    """Runs juror calls with a bounded concurrency and an optional QPM cap.

    ``max_concurrency`` bounds simultaneous in-flight calls (default 1 —
    safe for memory-constrained local hosts). ``rate_limit_per_min`` > 0
    enforces a minimum spacing between call starts (useful for cloud quotas);
    0 disables spacing. Each call is bounded by ``per_item_timeout``.
    """

    def __init__(self, max_concurrency: int = 1, rate_limit_per_min: int = 0,
                 per_item_timeout: int = 120):
        self.max_concurrency = max(1, int(max_concurrency))
        self.min_interval = 60.0 / rate_limit_per_min if rate_limit_per_min > 0 else 0.0
        self.per_item_timeout = per_item_timeout
        self._lock = threading.Lock()
        self._last_start = 0.0

    def _throttle(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.time()
            wait = self._last_start + self.min_interval - now
            if wait > 0:
                time.sleep(wait)
            self._last_start = time.time()

    def run(self, tasks: List[Tuple[str, Callable[[], str]]]) -> Dict[str, Any]:
        """Execute ``[(id, fn)]`` and return ``{id: result_or_JurorError}``.

        Results preserve per-task association; timeouts/exceptions become
        ``_JurorError`` sentinels so a single bad juror never aborts the vote.
        """
        results: Dict[str, Any] = {}

        def _wrapped(fn: Callable[[], str]) -> str:
            self._throttle()
            return fn()

        with ThreadPoolExecutor(max_workers=self.max_concurrency) as ex:
            future_to_id = {ex.submit(_wrapped, fn): tid for tid, fn in tasks}
            for future, tid in future_to_id.items():
                try:
                    results[tid] = future.result(timeout=self.per_item_timeout)
                except Exception as e:  # noqa: BLE001 — deliberately broad
                    logger.warning("  [Jury] juror '%s' failed: %s", tid, e)
                    results[tid] = _JurorError(str(e))
        return results


# ======================================================================
# Label normalization / tally helpers
# ======================================================================

def normalize_label(text: str, labels: Optional[List[str]]) -> Optional[str]:
    """Map a juror's raw answer onto one canonical label.

    With an explicit ``labels`` set, returns the first label that appears in
    the answer (word/substring match), applying common synonyms. Without a
    label set, returns a compact lowercased fingerprint of the answer.
    Returns None when nothing matches (juror abstains from the tally).
    """
    if text is None:
        return None
    cleaned = _strip_think(text).strip().lower()
    if not cleaned:
        return None

    if labels:
        wanted = [l.lower() for l in labels]
        # 1) direct label match (longest first to avoid 'true' matching in 'untrue')
        for lab in sorted(wanted, key=len, reverse=True):
            if re.search(r"\b" + re.escape(lab) + r"\b", cleaned):
                return lab
        # 2) synonym match
        for syn, canon in _LABEL_SYNONYMS.items():
            if canon in wanted and re.search(r"\b" + re.escape(syn) + r"\b", cleaned):
                return canon
        return None

    # No labels: fingerprint the whole (short) answer.
    return cleaned[:200]


# ======================================================================
# The jury
# ======================================================================

class VotingJury:
    """Coordinates jurors + judge to produce a verdict per decision.

    Parameters
    ----------
    config : VotingConfig
    tracer : optional object exposing ``trace_vote`` / ``trace_error``.
    juror_fns : optional ``{id: fn(prompt, max_tokens) -> str}`` to inject
        pre-built jurors (used by tests). When omitted, jurors are built from
        ``config.jurors``.
    judge_fn : optional pre-built judge str-fn (used by tests).
    """

    def __init__(self, config: VotingConfig, tracer: Any = None,
                 juror_fns: Optional[Dict[str, Callable[[str, int], str]]] = None,
                 judge_fn: Optional[Callable[[str, int], str]] = None,
                 run_id: Optional[str] = None):
        self.config = config
        self.tracer = tracer

        if juror_fns is not None:
            self.juror_ids = list(juror_fns.keys())
            self.juror_fns = dict(juror_fns)
        else:
            self.juror_ids = [j.id for j in config.jurors]
            self.juror_fns = {j.id: build_generate_fn(j) for j in config.jurors}

        if not self.juror_ids:
            raise ValueError("VotingJury requires at least one juror")

        # Judge function. `judge_is_juror` flags the self-preference risk.
        self.judge_id = config.judge.id if config.judge is not None else self._primary_id()
        self.judge_is_juror = self.judge_id in self.juror_ids
        if judge_fn is not None:
            self.judge_fn = judge_fn
        elif config.judge is not None:
            jspec = config.judge
            # Reuse a juror fn when the judge references an existing juror with
            # the same model; otherwise build a dedicated judge function.
            same_as_juror = any(
                j.id == jspec.id and j.model == jspec.model for j in config.jurors
            )
            if jspec.id in self.juror_fns and same_as_juror:
                self.judge_fn = self.juror_fns[jspec.id]
            else:
                self.judge_fn = build_generate_fn(jspec)
                self.judge_is_juror = False
        else:
            # No judge configured — fall back to the primary juror for tie-breaks.
            self.judge_fn = self.juror_fns[self._primary_id()]

        self.executor = RateLimitedExecutor(
            max_concurrency=config.pool.max_concurrency,
            rate_limit_per_min=config.pool.rate_limit_per_min,
            per_item_timeout=config.pool.per_juror_timeout_s,
        )

        # Reproducible RNG for anonymised candidate shuffling.
        self._rng = random.Random(config.seed)

        # Run identity + fingerprint so logs from different runs never mix.
        self.run_id = run_id or f"{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        self.fingerprint = {
            "jurors": {j.id: {"backend": j.backend, "model": j.model} for j in config.jurors}
            if config.jurors else {jid: {"backend": "injected"} for jid in self.juror_ids},
            "judge": {"id": self.judge_id, "is_juror": self.judge_is_juror},
            "judge_mode": config.judge_mode,
            "default_strategy": config.default_strategy,
            "decisions": {d: {"strategy": p.strategy, "labels": p.labels}
                          for d, p in config.decisions.items()},
            "seed": config.seed,
        }

        # Per-run log path so aggregate analysis never mixes juror panels.
        base = config.log_path or "results/voting_log.jsonl"
        log_dir = os.path.dirname(base) or "results"
        self.log_path = os.path.join(log_dir, f"voting_{self.run_id}.jsonl")
        self._write_run_header()

    def _write_run_header(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
            header = {
                "type": "run_header",
                "run_id": self.run_id,
                "ts": time.time(),
                "fingerprint": self.fingerprint,
            }
            with open(self.log_path, "a") as f:
                f.write(json.dumps(header) + "\n")
            logger.info("  [Jury] run_id=%s log=%s", self.run_id, self.log_path)
        except Exception as e:  # noqa: BLE001
            logger.debug("  [Jury] could not write run header: %s", e)

    # ---- public factory helpers ------------------------------------

    def _primary_id(self) -> str:
        if self.config.primary_juror and self.config.primary_juror in self.juror_fns:
            return self.config.primary_juror
        return self.juror_ids[0]

    def make_fn(self, default_decision: Optional[str] = None) -> Callable[..., str]:
        """Return a drop-in str-fn. Calls default to ``default_decision`` but an
        explicit ``decision=`` kwarg on the call overrides it."""
        def fn(prompt: str, max_tokens: int = 2048, decision: Optional[str] = None) -> str:
            return self.decide(prompt, max_tokens, decision or default_decision)
        return fn

    def make_llama_wrapper(self, default_decision: Optional[str] = None) -> Callable[..., Dict[str, Any]]:
        """Return a drop-in llama-cpp-style callable (Phase 1/2 shape)."""
        jury = self

        class _LlamaJuryWrapper:
            def __init__(self):
                self.n_ctx = lambda: 16384

            def __call__(self, prompt: str = "", max_tokens: int = 2048,
                         decision: Optional[str] = None, **kwargs) -> Dict[str, Any]:
                text = jury.decide(prompt, max_tokens, decision or default_decision)
                return {"choices": [{"text": text}]}

            def __getattr__(self, name):
                # Be tolerant of attribute probes from Phase 1/2 agents.
                raise AttributeError(name)

        return _LlamaJuryWrapper()

    # ---- core decision logic ---------------------------------------

    def decide(self, prompt: str, max_tokens: int, decision: Optional[str]) -> str:
        """Produce a verdict string for one decision.

        Voting fires only when ``decision`` is in the allowlist; otherwise the
        primary juror answers alone.
        """
        policy = self.config.decisions.get(decision) if decision else None
        if policy is None:
            # Not allowlisted -> single primary juror (no panel cost).
            return self._safe_call(self._primary_id(), prompt, max_tokens)

        t0 = time.time()
        # 1) Gather juror answers in parallel (bounded).
        tasks = [
            (jid, (lambda p=prompt, mt=max_tokens, f=self.juror_fns[jid]: f(p, mt)))
            for jid in self.juror_ids
        ]
        raw_results = self.executor.run(tasks)

        juror_records: List[Dict[str, Any]] = []
        valid: List[Tuple[str, str]] = []   # (juror_id, answer_text)
        for jid in self.juror_ids:
            res = raw_results.get(jid)
            if isinstance(res, _JurorError) or res is None:
                juror_records.append({"id": jid, "ok": False, "error": getattr(res, "message", "no response")})
                continue
            valid.append((jid, res))
            juror_records.append({"id": jid, "ok": True, "answer": res})

        if len(valid) < self.config.pool.min_valid_responses or not valid:
            # Not enough jurors responded — fall back to judge alone.
            verdict = self._safe_call_fn(self.judge_fn, "judge", prompt, max_tokens)
            self._emit_vote(decision, policy, juror_records, tally=None,
                            verdict=verdict, judge_reason="fallback: insufficient juror responses",
                            duration=time.time() - t0, extra={})
            return verdict

        strategy = policy.strategy or self.config.default_strategy
        if strategy == STRATEGY_MAJORITY:
            verdict, tally, reason, extra = self._aggregate_majority(prompt, max_tokens, valid, policy)
        elif strategy == STRATEGY_JUDGE_SYNTHESIZE:
            verdict, tally, reason, extra = self._aggregate_synthesize(prompt, max_tokens, valid)
        else:  # judge_select (default)
            verdict, tally, reason, extra = self._aggregate_judge_select(prompt, max_tokens, valid)

        # annotate records with normalized labels for the log
        if strategy == STRATEGY_MAJORITY:
            for rec in juror_records:
                if rec.get("ok"):
                    ans = next((a for j, a in valid if j == rec["id"]), None)
                    rec["label"] = normalize_label(ans, policy.labels)

        self._emit_vote(decision, policy, juror_records, tally=tally,
                        verdict=verdict, judge_reason=reason, duration=time.time() - t0,
                        extra=extra)
        return verdict

    # ---- aggregation strategies ------------------------------------

    def _aggregate_majority(self, prompt: str, max_tokens: int,
                            valid: List[Tuple[str, str]],
                            policy: DecisionPolicy) -> Tuple[str, Dict[str, int], str, Dict[str, Any]]:
        """Categorical majority vote. Judge breaks ties (or always decides)."""
        labels = policy.labels
        tally: Dict[str, int] = {}
        label_to_answer: Dict[str, str] = {}
        for jid, ans in valid:
            lab = normalize_label(ans, labels)
            if lab is None:
                continue
            tally[lab] = tally.get(lab, 0) + 1
            label_to_answer.setdefault(lab, ans)

        judge_mode = policy.judge_mode or self.config.judge_mode

        if not tally:
            # Nobody produced a recognizable label -> judge decides from scratch.
            verdict = self._judge_pick_label(prompt, max_tokens, valid, labels)
            return verdict, tally, "no recognizable labels; judge decided", {}

        top = max(tally.values())
        winners = [lab for lab, c in tally.items() if c == top]

        if judge_mode == JUDGE_ALWAYS:
            verdict = self._judge_pick_label(prompt, max_tokens, valid, labels)
            return verdict, tally, "judge_mode=always", {}

        if len(winners) == 1:
            return label_to_answer[winners[0]], tally, "clear majority", {}

        # Tie.
        if self.config.tie_breaker == "first":
            first_lab = next(normalize_label(a, labels) for _, a in valid
                             if normalize_label(a, labels) in winners)
            return label_to_answer[first_lab], tally, "tie -> first juror", {}
        if self.config.tie_breaker == "primary":
            pid = self._primary_id()
            p_ans = next((a for j, a in valid if j == pid), None)
            p_lab = normalize_label(p_ans, labels) if p_ans else None
            if p_lab in winners:
                return label_to_answer[p_lab], tally, "tie -> primary juror", {}
        # default: judge breaks the tie among the tied labels
        verdict = self._judge_pick_label(prompt, max_tokens, valid, winners)
        return verdict, tally, f"tie among {winners}; judge broke tie", {}

    def _aggregate_judge_select(self, prompt: str, max_tokens: int,
                                valid: List[Tuple[str, str]]) -> Tuple[str, Dict[str, int], str, Dict[str, Any]]:
        """Judge picks the single best candidate; its raw text is returned unchanged.

        Candidates are shuffled and presented anonymously (``Candidate N`` with
        no juror id) so the judge cannot favour a known model or a fixed
        position. The visible ordering is recorded for position-bias analysis.
        """
        if len(valid) == 1:
            return valid[0][1], {valid[0][0]: 1}, "single juror", {}

        answer_of = {jid: ans for jid, ans in valid}
        rotations = self._resolve_rotations(len(valid))

        # Base anonymous order (shuffled once, reproducibly).
        base = list(range(len(valid)))
        self._rng.shuffle(base)

        def _ask(order_idx: List[int]) -> Tuple[Optional[str], int, str]:
            shuffled = [valid[i] for i in order_idx]
            block = "\n\n".join(f"--- CANDIDATE {i} ---\n{ans}"
                                for i, (_jid, ans) in enumerate(shuffled))
            judge_prompt = (
                "You are the judge of a panel. Several anonymous candidates independently "
                "answered the same task. Pick the SINGLE best candidate answer.\n\n"
                "Judge only on merit: correctness, completeness, and adherence to the "
                "requested output format (e.g. valid JSON). The candidates are anonymous "
                "and their order is random.\n\n"
                f"ORIGINAL TASK:\n{prompt[:4000]}\n\n"
                f"CANDIDATE ANSWERS:\n{block}\n\n"
                'Respond with ONLY strict JSON: {"choice": <candidate_number>, "reason": "<short>"}'
            )
            raw = self._safe_call_fn(self.judge_fn, "judge", judge_prompt, 256)
            vis, why = self._parse_choice(raw, len(shuffled))
            if vis is None:
                return None, 0, why
            return shuffled[vis][0], vis, why  # (juror_id, visible_pos, reason)

        if rotations <= 1:
            # Single anonymous shuffle (fast path).
            chosen_id, vis_idx, reason = _ask(base)
            extra = {"visible_order": [jid for jid, _ in (valid[i] for i in base)],
                     "judge_is_juror": self.judge_is_juror}
            if chosen_id is None:
                chosen_id = valid[base[0]][0]
                extra["chosen_visible_pos"] = 0
                tally = {jid: (1 if jid == chosen_id else 0) for jid, _ in valid}
                return answer_of[chosen_id], tally, "judge parse failed -> first (shuffled) candidate", extra
            extra["chosen_visible_pos"] = vis_idx
            tally = {jid: (1 if jid == chosen_id else 0) for jid, _ in valid}
            return answer_of[chosen_id], tally, f"judge selected -> {chosen_id}: {reason}", extra

        # Position-balanced selection: present the candidates in `rotations`
        # cyclic orders so each candidate occupies each position; tally the
        # judge's pick across rotations. This neutralises primacy/position bias.
        vote_counts = {jid: 0 for jid, _ in valid}
        picks: List[Optional[str]] = []
        n = len(valid)
        for r in range(rotations):
            order_idx = base[r % n:] + base[:r % n]  # cyclic rotation of the base order
            cid, _vis, _why = _ask(order_idx)
            if cid is None:
                cid = valid[order_idx[0]][0]
            vote_counts[cid] += 1
            picks.append(cid)

        best = max(vote_counts.values())
        winners = [jid for jid, _ in valid if vote_counts[jid] == best]  # stable by juror order
        winner_id = winners[0]
        extra = {
            "visible_order": [jid for jid, _ in (valid[i] for i in base)],
            "judge_is_juror": self.judge_is_juror,
            "rotations": rotations,
            "rotation_picks": picks,
        }
        reason = f"position-balanced over {rotations} rotations -> {winner_id} {vote_counts}"
        return answer_of[winner_id], dict(vote_counts), reason, extra

    def _resolve_rotations(self, n_candidates: int) -> int:
        r = self.config.judge_rotations
        if isinstance(r, str) and r.strip().lower() == "auto":
            return n_candidates
        try:
            r = int(r)
        except (TypeError, ValueError):
            return 1
        return max(1, min(r, n_candidates))

    def _aggregate_synthesize(self, prompt: str, max_tokens: int,
                              valid: List[Tuple[str, str]]) -> Tuple[str, Dict[str, int], str, Dict[str, Any]]:
        """Judge merges candidates into a new answer (free-form text only)."""
        candidates_block = "\n\n".join(
            f"--- CANDIDATE {i} ---\n{ans}" for i, (_jid, ans) in enumerate(valid)
        )
        judge_prompt = (
            "You are the judge of a panel. Synthesize the anonymous candidate answers "
            "below into one best final answer. Keep the requested output format.\n\n"
            f"ORIGINAL TASK:\n{prompt[:4000]}\n\n"
            f"CANDIDATE ANSWERS:\n{candidates_block}\n\n"
            "Final answer:"
        )
        verdict = self._safe_call_fn(self.judge_fn, "judge", judge_prompt, max_tokens)
        return verdict, {jid: 0 for jid, _ in valid}, "judge synthesized", {}

    def _judge_pick_label(self, prompt: str, max_tokens: int,
                          valid: List[Tuple[str, str]],
                          labels: Optional[List[str]]) -> str:
        """Ask the judge to choose one label; return a juror answer bearing it.

        Falls back to a juror answer if the judge output can't be mapped.
        """
        label_hint = f"Choose exactly one of: {labels}." if labels else \
            "Choose the single best answer."
        opinions = "\n".join(f"- juror {jid}: {_strip_think(a)[:300]}" for jid, a in valid)
        judge_prompt = (
            "You are the judge of a panel deciding a categorical question. "
            f"{label_hint}\n\n"
            f"ORIGINAL TASK:\n{prompt[:4000]}\n\n"
            f"JUROR OPINIONS:\n{opinions}\n\n"
            "Respond with ONLY the chosen label."
        )
        raw = self._safe_call_fn(self.judge_fn, "judge", judge_prompt, 128)
        chosen = normalize_label(raw, labels)
        if chosen is not None:
            # return a juror answer that matches, else the judge's own text
            for jid, a in valid:
                if normalize_label(a, labels) == chosen:
                    return a
            return raw
        # Judge unmappable -> return first juror answer.
        return valid[0][1]

    # ---- call helpers ----------------------------------------------

    def _safe_call(self, juror_id: str, prompt: str, max_tokens: int) -> str:
        return self._safe_call_fn(self.juror_fns[juror_id], juror_id, prompt, max_tokens)

    def _safe_call_fn(self, fn: Callable[[str, int], str], who: str,
                      prompt: str, max_tokens: int) -> str:
        try:
            return fn(prompt, max_tokens) or ""
        except Exception as e:  # noqa: BLE001
            logger.warning("  [Jury] call to '%s' failed: %s", who, e)
            if self.tracer is not None:
                try:
                    self.tracer.trace_error("Jury", f"{who} call failed: {e}")
                except Exception:
                    pass
            return ""

    @staticmethod
    def _parse_choice(raw: str, n: int) -> Tuple[Optional[int], str]:
        """Extract a candidate index from the judge's JSON (or loose text)."""
        text = _strip_think(raw or "")
        # Try strict JSON first.
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                obj = json.loads(m.group(0))
                choice = obj.get("choice")
                reason = str(obj.get("reason", ""))[:200]
                if choice is not None:
                    idx = int(choice)
                    if 0 <= idx < n:
                        return idx, reason
            except (ValueError, TypeError, json.JSONDecodeError):
                pass
        # Fallback: first integer in range.
        for num in re.findall(r"\d+", text):
            idx = int(num)
            if 0 <= idx < n:
                return idx, "parsed from loose text"
        return None, "unparseable"

    # ---- explainability --------------------------------------------

    def _emit_vote(self, decision: Optional[str], policy: DecisionPolicy,
                   juror_records: List[Dict[str, Any]], tally: Optional[Dict[str, int]],
                   verdict: str, judge_reason: str, duration: float,
                   extra: Optional[Dict[str, Any]] = None) -> None:
        strategy = policy.strategy if policy else "single"
        extra = extra or {}
        # Trace event for the HTML report.
        if self.tracer is not None:
            try:
                self.tracer.trace_vote(
                    decision=decision or "untagged",
                    strategy=strategy,
                    jurors=juror_records,
                    tally=tally or {},
                    verdict=verdict,
                    judge_reason=judge_reason,
                    duration=duration,
                )
            except AttributeError:
                # Tracer without trace_vote — degrade to info if available.
                try:
                    self.tracer.trace_info("Jury", f"vote[{decision}] -> {judge_reason}")
                except Exception:
                    pass
            except Exception:
                pass
        # Append to the per-run JSONL log for offline agreement analysis.
        try:
            os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
            record = {
                "type": "vote",
                "run_id": self.run_id,
                "ts": time.time(),
                "decision": decision,
                "strategy": strategy,
                "labels": policy.labels if policy else None,
                "jurors": [
                    {k: v for k, v in r.items() if k in ("id", "ok", "label", "error")}
                    for r in juror_records
                ],
                "tally": tally or {},
                "judge_id": self.judge_id,
                "judge_is_juror": self.judge_is_juror,
                "visible_order": extra.get("visible_order"),
                "chosen_visible_pos": extra.get("chosen_visible_pos"),
                "rotations": extra.get("rotations"),
                "rotation_picks": extra.get("rotation_picks"),
                "judge_reason": judge_reason,
                "duration_s": round(duration, 2),
                "verdict_preview": (verdict or "")[:300],
            }
            with open(self.log_path, "a") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:  # noqa: BLE001
            logger.debug("  [Jury] could not write voting log: %s", e)


def build_jury(config: VotingConfig, tracer: Any = None,
               run_id: Optional[str] = None) -> Optional[VotingJury]:
    """Convenience constructor. Returns None when voting is disabled/empty."""
    if not config or not config.enabled or not config.jurors:
        return None
    return VotingJury(config, tracer=tracer, run_id=run_id)
