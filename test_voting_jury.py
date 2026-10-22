#!/usr/bin/env python3
"""
Unit tests for the jury voting system (orchestration/voting_jury.py).

Runs without any models — jurors and judge are injected as simple callables.

    python test_voting_jury.py
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from orchestration.voting_jury import (
    VotingConfig, DecisionPolicy, PoolConfig, VotingJury,
    normalize_label, parse_voting_config,
    STRATEGY_MAJORITY, STRATEGY_JUDGE_SELECT, JUDGE_ALWAYS,
)

_PASSED = 0
_FAILED = 0


def check(name, cond):
    global _PASSED, _FAILED
    if cond:
        _PASSED += 1
        print(f"  PASS  {name}")
    else:
        _FAILED += 1
        print(f"  FAIL  {name}")


def const_juror(answer):
    """A juror that always returns the same answer."""
    return lambda prompt, max_tokens=2048, **kw: answer


_TMPDIR = tempfile.mkdtemp(prefix="voting_test_")


def _cfg(decisions, **kw):
    kw.setdefault("seed", 12345)  # deterministic candidate shuffling
    return VotingConfig(
        enabled=True,
        jurors=[],  # jurors injected via juror_fns
        judge=None,
        pool=PoolConfig(max_concurrency=1, min_valid_responses=1),
        decisions=decisions,
        log_path=os.path.join(_TMPDIR, "voting_log.jsonl"),
        **kw,
    )


def test_normalize_label():
    print("\n[normalize_label]")
    check("direct label", normalize_label("I choose fuzz here", ["fuzz", "replan"]) == "fuzz")
    check("word boundary", normalize_label("untrue statement", ["true", "false"]) is None)
    check("synonym SUCCESS->true", normalize_label("SUCCESS: injected", ["true", "false"]) == "true")
    check("synonym FAILURE->false", normalize_label("FAILURE: nope", ["true", "false"]) == "false")
    check("strips think", normalize_label("<think>hmm abort</think>replan", ["replan", "abort"]) == "replan")
    check("no match", normalize_label("banana", ["fuzz", "abort"]) is None)


def test_majority_clear():
    print("\n[majority_vote — clear majority]")
    jurors = {"a": const_juror("fuzz"), "b": const_juror("fuzz"), "c": const_juror("replan")}
    cfg = _cfg({"phase3.recovery": DecisionPolicy(
        strategy=STRATEGY_MAJORITY, labels=["fuzz", "replan", "fix_infra", "abort"])})
    jury = VotingJury(cfg, juror_fns=jurors, judge_fn=const_juror("abort"))
    verdict = jury.decide("prompt", 256, "phase3.recovery")
    check("2x fuzz beats 1x replan", "fuzz" in verdict.lower())


def test_majority_tie_judge():
    print("\n[majority_vote — tie broken by judge]")
    jurors = {"a": const_juror("fuzz"), "b": const_juror("replan")}
    cfg = _cfg({"phase3.recovery": DecisionPolicy(
        strategy=STRATEGY_MAJORITY, labels=["fuzz", "replan", "fix_infra", "abort"])})
    # judge picks 'replan'
    jury = VotingJury(cfg, juror_fns=jurors, judge_fn=const_juror("replan"))
    verdict = jury.decide("prompt", 256, "phase3.recovery")
    check("judge breaks tie -> replan", "replan" in verdict.lower())


def test_judge_mode_always():
    print("\n[majority_vote — judge_mode=always]")
    jurors = {"a": const_juror("fuzz"), "b": const_juror("fuzz")}
    cfg = _cfg({"phase3.recovery": DecisionPolicy(
        strategy=STRATEGY_MAJORITY, labels=["fuzz", "abort"], judge_mode=JUDGE_ALWAYS)})
    # Even though jurors agree on fuzz, judge_mode=always lets the judge decide -> abort
    jury = VotingJury(cfg, juror_fns=jurors, judge_fn=const_juror("abort"))
    verdict = jury.decide("prompt", 256, "phase3.recovery")
    check("judge overrides to abort", "abort" in verdict.lower())


def test_judge_select():
    print("\n[judge_select — verbatim + correct id mapping under shuffle]")
    answers = {"a": '{"plan": "A"}', "b": '{"plan": "B"}', "c": '{"plan": "C"}'}
    jurors = {k: const_juror(v) for k, v in answers.items()}
    cfg = _cfg({"phase3.plan": DecisionPolicy(strategy=STRATEGY_JUDGE_SELECT)})
    # Judge picks visible position 1 (post-shuffle); the jury must map it back
    # to the correct juror and return that juror's raw text unchanged.
    jury = VotingJury(cfg, juror_fns=jurors, judge_fn=const_juror('{"choice": 1, "reason": "best"}'))
    verdict = jury.decide("make a plan", 2048, "phase3.plan")
    check("verdict is a candidate verbatim", verdict in answers.values())
    # invariant: exactly one juror flagged in tally, and its answer == verdict
    check("mapping is consistent", verdict == answers[_winner_of(jury, verdict, answers)])


def _winner_of(jury, verdict, answers):
    """Recompute the winning juror id from the last vote log record."""
    import json as _json
    with open(jury.log_path) as f:
        last = [ _json.loads(l) for l in f if l.strip() and _json.loads(l).get("type") == "vote" ][-1]
    won = [jid for jid, c in (last.get("tally") or {}).items() if c == 1]
    return won[0] if won else None


def test_judge_select_anonymity():
    print("\n[judge_select — candidates presented anonymously]")
    seen = {}
    def recording_judge(prompt, max_tokens=2048, **kw):
        seen["prompt"] = prompt
        return '{"choice": 0, "reason": "x"}'
    jurors = {"deepseek": const_juror("ANS_D"), "llama": const_juror("ANS_L"),
              "gemma": const_juror("ANS_G")}
    cfg = _cfg({"phase3.plan": DecisionPolicy(strategy=STRATEGY_JUDGE_SELECT)})
    jury = VotingJury(cfg, juror_fns=jurors, judge_fn=recording_judge)
    verdict = jury.decide("task", 2048, "phase3.plan")
    p = seen.get("prompt", "")
    check("no juror ids leak to judge", not any(jid in p for jid in jurors))
    check("anonymous candidate labels present", "CANDIDATE 0" in p)
    check("verdict is a juror answer", verdict in ("ANS_D", "ANS_L", "ANS_G"))


def test_rotation_position_balance():
    print("\n[judge_select — rotations neutralise a primacy-biased judge]")
    import json as _json
    answers = {"a": "AAA", "b": "BBB", "c": "CCC"}
    jurors = {k: const_juror(v) for k, v in answers.items()}
    # Judge with EXTREME primacy bias: always picks candidate 0.
    biased_judge = lambda p, mt=2048, **k: '{"choice": 0, "reason": "always first"}'
    cfg = _cfg({"phase3.plan": DecisionPolicy(strategy=STRATEGY_JUDGE_SELECT)},
               judge_rotations="auto")
    jury = VotingJury(cfg, juror_fns=jurors, judge_fn=biased_judge)
    verdict = jury.decide("task", 2048, "phase3.plan")
    with open(jury.log_path) as f:
        last = [_json.loads(l) for l in f if l.strip() and _json.loads(l).get("type") == "vote"][-1]
    tally = last.get("tally") or {}
    # With 3 cyclic rotations and a pos0-only judge, each juror is chosen exactly once.
    check("rotations recorded", last.get("rotations") == 3)
    check("position bias balanced (each juror 1 pick)", sorted(tally.values()) == [1, 1, 1])
    check("verdict is a candidate answer", verdict in answers.values())


def test_run_header_and_fingerprint():
    print("\n[run_id + per-run log header]")
    jurors = {"deepseek": const_juror("x"), "llama": const_juror("y")}
    cfg = _cfg({"phase3.plan": DecisionPolicy(strategy=STRATEGY_JUDGE_SELECT)},
               primary_juror="deepseek")
    # judge is a juror id -> self-pref flag should be True
    from orchestration.voting_jury import JurorSpec
    cfg.judge = JurorSpec(id="deepseek", backend="injected", model="deepseek")
    jury = VotingJury(cfg, juror_fns=jurors, judge_fn=const_juror('{"choice":0}'))
    check("run_id assigned", bool(jury.run_id))
    check("judge_is_juror flag", jury.judge_is_juror is True)
    import json as _json
    with open(jury.log_path) as f:
        first = _json.loads(f.readline())
    check("first line is run_header", first.get("type") == "run_header")
    check("header has fingerprint", "fingerprint" in first and "judge" in first["fingerprint"])


def test_not_allowlisted_single():
    print("\n[allowlist gating — non-listed decision uses primary juror]")
    calls = {"a": 0, "b": 0}

    def counting(jid):
        def fn(prompt, max_tokens=2048, **kw):
            calls[jid] += 1
            return jid
        return fn

    jurors = {"a": counting("a"), "b": counting("b")}
    cfg = _cfg({"phase3.plan": DecisionPolicy(strategy=STRATEGY_JUDGE_SELECT)},
               primary_juror="a")
    jury = VotingJury(cfg, juror_fns=jurors, judge_fn=const_juror("x"))
    verdict = jury.decide("prompt", 256, "phase3.recovery")  # not in allowlist
    check("verdict from primary juror", verdict == "a")
    check("only primary juror called", calls["a"] == 1 and calls["b"] == 0)


def test_untagged_single():
    print("\n[untagged call uses primary juror]")
    jurors = {"a": const_juror("primary"), "b": const_juror("other")}
    cfg = _cfg({}, primary_juror="a")
    jury = VotingJury(cfg, juror_fns=jurors, judge_fn=const_juror("x"))
    check("decision=None -> primary", jury.decide("p", 256, None) == "primary")


def test_failed_juror_fallback():
    print("\n[juror failure handling]")
    def boom(prompt, max_tokens=2048, **kw):
        raise RuntimeError("juror down")

    jurors = {"a": boom, "b": const_juror("fuzz")}
    cfg = _cfg({"phase3.recovery": DecisionPolicy(
        strategy=STRATEGY_MAJORITY, labels=["fuzz", "abort"])})
    jury = VotingJury(cfg, juror_fns=jurors, judge_fn=const_juror("abort"))
    verdict = jury.decide("prompt", 256, "phase3.recovery")
    check("survivor decides", "fuzz" in verdict.lower())


def test_llama_wrapper_shape():
    print("\n[llama wrapper returns dict shape]")
    jurors = {"a": const_juror("fuzz"), "b": const_juror("fuzz")}
    cfg = _cfg({"phase3.recovery": DecisionPolicy(
        strategy=STRATEGY_MAJORITY, labels=["fuzz", "abort"])})
    jury = VotingJury(cfg, juror_fns=jurors, judge_fn=const_juror("abort"))
    wrapper = jury.make_llama_wrapper("phase3.recovery")
    out = wrapper(prompt="p", max_tokens=256)
    check("dict with choices", isinstance(out, dict) and "choices" in out)
    check("text present", "fuzz" in out["choices"][0]["text"].lower())


def test_make_fn_override():
    print("\n[make_fn default vs per-call override]")
    jurors = {"a": const_juror("fuzz"), "b": const_juror("fuzz"), "c": const_juror("fuzz")}
    cfg = _cfg({
        "phase3.recovery": DecisionPolicy(strategy=STRATEGY_MAJORITY, labels=["fuzz", "abort"]),
    }, primary_juror="a")
    jury = VotingJury(cfg, juror_fns=jurors, judge_fn=const_juror("abort"))
    fn = jury.make_fn("phase3.plan")  # default tag not allowlisted -> single juror
    check("default tag not allowlisted -> single", fn("p", 256) == "fuzz")
    # explicit override to an allowlisted categorical decision -> voting path
    verdict = fn("p", 256, decision="phase3.recovery")
    check("override to voting", "fuzz" in verdict.lower())


def test_parse_config():
    print("\n[parse_voting_config]")
    raw = {
        "voting": {
            "enabled": True,
            "jurors": [
                {"id": "d", "backend": "ollama", "model": "deepseek-r1:14b"},
                {"id": "q", "backend": "ollama", "model": "qwen"},
            ],
            "judge": {"id": "d", "mode": "always"},
            "default_strategy": "judge_select",
            "pool": {"max_concurrency": 2, "per_juror_timeout_s": 90},
            "decisions": {
                "phase3.recovery": {"strategy": "majority_vote", "labels": ["fuzz", "abort"]},
            },
        }
    }
    cfg = parse_voting_config(raw)
    check("enabled", cfg.enabled)
    check("2 jurors", len(cfg.jurors) == 2)
    check("judge mode always", cfg.judge_mode == "always")
    check("judge reuses juror d", cfg.judge.id == "d")
    check("pool concurrency", cfg.pool.max_concurrency == 2)
    check("decision parsed", cfg.decisions["phase3.recovery"].labels == ["fuzz", "abort"])
    check("label()", cfg.label() == "jury[d,q]")


def main():
    test_normalize_label()
    test_majority_clear()
    test_majority_tie_judge()
    test_judge_mode_always()
    test_judge_select()
    test_judge_select_anonymity()
    test_rotation_position_balance()
    test_run_header_and_fingerprint()
    test_not_allowlisted_single()
    test_untagged_single()
    test_failed_juror_fallback()
    test_llama_wrapper_shape()
    test_make_fn_override()
    test_parse_config()

    print(f"\n{'='*40}\n  {_PASSED} passed, {_FAILED} failed\n{'='*40}")
    sys.exit(1 if _FAILED else 0)


if __name__ == "__main__":
    main()
