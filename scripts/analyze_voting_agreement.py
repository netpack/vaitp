#!/usr/bin/env python3
"""
Inter-juror agreement + judge-behaviour analysis for the VAITP voting jury.

Reads a per-run JSONL voting log written by ``orchestration/voting_jury.py``
and reports, grouped by ``run_id`` so different juror panels never mix:

  * Fleiss' kappa per categorical (``majority_vote``) decision — extends the
    Cohen's kappa reported in the EMSE paper to the multi-rater case.
  * Judge-selection distribution for ``judge_select`` decisions (which juror the
    judge picked), with a self-preference indicator when the judge is a juror.
  * Position-bias check: distribution of the chosen *visible* position (should
    be ~uniform because candidates are shuffled and anonymised).

Usage:
    python scripts/analyze_voting_agreement.py --log results/voting_<run_id>.jsonl
    python scripts/analyze_voting_agreement.py --log results/voting_<run_id>.jsonl --json summary.json
    python scripts/analyze_voting_agreement.py --log results/voting_<run_id>.jsonl --run-id <id>
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict

DEFAULT_LOG = "results/voting_log.jsonl"


def interpret(kappa):
    """Landis & Koch interpretation of a kappa value."""
    if kappa is None or kappa != kappa:  # None or NaN
        return "undefined"
    if kappa < 0:
        return "poor (worse than chance)"
    if kappa <= 0.20:
        return "slight"
    if kappa <= 0.40:
        return "fair"
    if kappa <= 0.60:
        return "moderate"
    if kappa <= 0.80:
        return "substantial"
    return "almost perfect"


def fleiss_kappa(items, raters, categories):
    """Compute Fleiss' kappa.

    items: list of dicts {rater_id: category}. Missing raters -> 'abstain'.
    raters: ordered list of rater ids (fixed n across items).
    categories: list of category labels (including 'abstain').
    Returns (kappa, N_items, n_raters, k_categories).
    """
    n = len(raters)
    N = len(items)
    if N == 0 or n < 2:
        return float("nan"), N, n, len(categories)

    cat_index = {c: j for j, c in enumerate(categories)}
    k = len(categories)

    nij = [[0] * k for _ in range(N)]
    for i, item in enumerate(items):
        for r in raters:
            cat = item.get(r, "abstain")
            nij[i][cat_index[cat]] += 1

    total = N * n
    p_j = [sum(nij[i][j] for i in range(N)) / total for j in range(k)]

    P_i = []
    for i in range(N):
        s = sum(nij[i][j] ** 2 for j in range(k))
        P_i.append((s - n) / (n * (n - 1)))
    P_bar = sum(P_i) / N
    P_e = sum(pj ** 2 for pj in p_j)

    if abs(1 - P_e) < 1e-12:
        return float("nan"), N, n, k
    return (P_bar - P_e) / (1 - P_e), N, n, k


def load_records(path):
    """Return (headers_by_run, votes_by_run). Legacy records go under 'legacy'."""
    headers = {}
    votes = defaultdict(list)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            run_id = rec.get("run_id", "legacy")
            if rec.get("type") == "run_header":
                headers[run_id] = rec.get("fingerprint", {})
            else:
                votes[run_id].append(rec)
    return headers, votes


def analyze_run(run_id, fingerprint, records):
    """Return a summary dict for one run and print a human report."""
    print(f"\n{'='*72}\n  RUN {run_id}\n{'='*72}")
    if fingerprint:
        jurors = list(fingerprint.get("jurors", {}).keys())
        judge = fingerprint.get("judge", {})
        print(f"  jurors={jurors}  judge={judge.get('id')} "
              f"(is_juror={judge.get('is_juror')})  seed={fingerprint.get('seed')}")

    summary = {"run_id": run_id, "fingerprint": fingerprint,
               "categorical": {}, "judge_select": {}}

    by_decision = defaultdict(list)
    for r in records:
        by_decision[r.get("decision")].append(r)

    # ---- categorical (majority_vote) -> Fleiss' kappa ----
    print("\n  Categorical decisions (Fleiss' kappa):")
    any_cat = False
    for decision, recs in sorted(by_decision.items(), key=lambda x: str(x[0])):
        maj = [r for r in recs if r.get("strategy") == "majority_vote"]
        if not maj:
            continue
        any_cat = True
        raters = sorted({j["id"] for r in maj for j in r.get("jurors", [])})
        categories = {"abstain"}
        items = []
        for r in maj:
            item = {}
            for j in r.get("jurors", []):
                lab = j.get("label")
                cat = lab if (j.get("ok") and lab is not None) else "abstain"
                item[j["id"]] = cat
                categories.add(cat)
            items.append(item)
        categories = sorted(categories)
        kappa, N, n, k = fleiss_kappa(items, raters, categories)
        kval = None if (kappa != kappa) else round(kappa, 4)
        print(f"    {decision}: votes={N} jurors={n} kappa={kval} ({interpret(kappa)})")
        summary["categorical"][decision] = {
            "votes": N, "jurors": n, "categories": k, "raters": raters,
            "fleiss_kappa": kval, "interpretation": interpret(kappa),
        }
    if not any_cat:
        print("    (none)")

    # ---- judge_select -> selection distribution + position bias ----
    print("\n  Generative decisions (judge_select):")
    sel_recs = [r for r in records if r.get("strategy") == "judge_select"]
    if not sel_recs:
        print("    (none)")
    else:
        winners = Counter()
        positions = Counter()
        n_multi = 0
        for r in sel_recs:
            tally = r.get("tally") or {}
            won = [jid for jid, c in tally.items() if c == 1]
            if won:
                winners[won[0]] += 1
            if r.get("chosen_visible_pos") is not None:
                positions[r["chosen_visible_pos"]] += 1
            if r.get("visible_order"):
                n_multi += 1
        total_sel = sum(winners.values())
        print(f"    verdicts={len(sel_recs)}  contested(multi-juror)={n_multi}")
        judge = (fingerprint or {}).get("judge", {})
        for jid, c in winners.most_common():
            share = (c / total_sel * 100) if total_sel else 0
            flag = "  <-- judge==juror (self-pref risk)" if judge.get("is_juror") and jid == judge.get("id") else ""
            print(f"      selected {jid}: {c} ({share:.1f}%){flag}")
        if positions:
            pos_total = sum(positions.values())
            pos_str = ", ".join(f"pos{p}={positions[p]} ({positions[p]/pos_total*100:.0f}%)"
                                for p in sorted(positions))
            print(f"    chosen visible position (want ~uniform): {pos_str}")
        summary["judge_select"] = {
            "verdicts": len(sel_recs),
            "contested": n_multi,
            "winners": dict(winners),
            "positions": {str(k): v for k, v in positions.items()},
            "judge_is_juror": judge.get("is_juror"),
        }
    return summary


def main():
    ap = argparse.ArgumentParser(description="Jury agreement + judge-behaviour analysis")
    ap.add_argument("--log", default=DEFAULT_LOG, help=f"per-run voting log (default: {DEFAULT_LOG})")
    ap.add_argument("--run-id", default=None, help="only analyze this run_id")
    ap.add_argument("--json", default=None, help="optional path to write a JSON summary")
    args = ap.parse_args()

    if not os.path.exists(args.log):
        print(f"Voting log not found: {args.log}")
        sys.exit(1)

    headers, votes = load_records(args.log)
    run_ids = [args.run_id] if args.run_id else sorted(votes.keys())

    summaries = {}
    for run_id in run_ids:
        if run_id not in votes:
            print(f"No vote records for run_id={run_id}")
            continue
        summaries[run_id] = analyze_run(run_id, headers.get(run_id, {}), votes[run_id])

    print(f"\n{'='*72}")
    if not summaries:
        print("  No vote records found.")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(summaries, f, indent=2)
        print(f"  Summary written to: {args.json}")


if __name__ == "__main__":
    main()
