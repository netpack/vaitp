#!/usr/bin/env python3
"""
VAITP Phase 0: Zero-Day Discovery Mode

Takes a git repository URL or local path and autonomously searches for
zero-day vulnerabilities using multi-stage reasoning.

Usage:
    # Basic scan (built-in tests + LLM hypotheses):
    python run_discovery.py https://github.com/user/repo

    # Surface mapping only (fast, no LLM):
    python run_discovery.py /path/to/repo --surface-only

    # LLM-only mode (skip built-in static tests):
    python run_discovery.py /path/to/repo --llm-only

    # With LLM review of findings:
    python run_discovery.py /path/to/repo --llm-review

    # Generate disclosure report for findings:
    python run_discovery.py /path/to/repo --generate-disclosure

    # Show taint flows (source-to-sink data flow):
    python run_discovery.py /path/to/repo --taint

    # Full pipeline with all features:
    python run_discovery.py /path/to/repo --llm-review --generate-disclosure --taint
"""
import argparse
import logging
import os
import sys
import subprocess
import json
import time
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def clone_repo(url: str, target_dir: str = None) -> str:
    """Clone a git repository and return the local path."""
    if target_dir is None:
        repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")
        target_dir = os.path.join("target_repos", repo_name)

    if os.path.isdir(target_dir):
        logger.info(f"Repository already exists at {target_dir}")
        return target_dir

    logger.info(f"Cloning {url} → {target_dir}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", url, target_dir],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.error(f"Clone failed: {result.stderr}")
        sys.exit(1)

    return target_dir


def create_ollama_fn(model: str):
    """Create a generate function using Ollama."""
    import requests

    def generate(prompt: str, max_tokens: int = 2048, **kwargs) -> str:
        # Extra kwargs (e.g. `decision`) accepted for jury API parity, ignored here.
        try:
            resp = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "num_predict": max_tokens,
                        "num_ctx": 8192,
                        "temperature": 0.3,
                    },
                },
                timeout=300,
            )
            resp.raise_for_status()
            response = resp.json().get("response", "")
            # Strip thinking tags for reasoning models
            if "</think>" in response:
                response = response.split("</think>", 1)[1].strip()
            return response
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return ""

    return generate


def llm_review_findings(findings, llm_fn, repo_name: str):
    """Use LLM to review and assess each finding."""
    from orchestration.discovery_agent import SEVERITY_SYSTEM_PROMPT, _extract_json

    reviewed = []
    for finding in findings:
        prompt = f"""{SEVERITY_SYSTEM_PROMPT}

Repository: {repo_name}
Category: {finding.category.value}
Title: {finding.title}
File: {finding.affected_file}:{finding.affected_function}
CWE: {finding.cwe}
Test Output: {finding.test_results.get('output', '')[:500]}
Confirmed: {finding.confirmed}

Assess this finding."""

        response = llm_fn(prompt, max_tokens=1024)
        assessment = _extract_json(response)
        if assessment:
            finding.severity = assessment.get("severity", finding.severity)
            finding.description = (
                f"{finding.description}\n\n"
                f"LLM Assessment: {assessment.get('reasoning', '')}\n"
                f"CVE Likelihood: {assessment.get('cve_likelihood', 'unknown')}\n"
                f"Recommended: {assessment.get('recommended_action', 'unknown')}"
            )
        reviewed.append(finding)
    return reviewed


def generate_disclosure_report(findings, repo_name: str, repo_url: str = ""):
    """Generate a disclosure report for confirmed findings."""
    reports = []
    for finding in findings:
        if not finding.confirmed:
            continue

        report = f"""# Security Finding: {finding.title}

## Summary

**Library:** {repo_name} ({repo_url})
**Severity:** {finding.severity.upper()}
**CWE:** {finding.cwe}
**Category:** {finding.category.value}
**Affected File:** {finding.affected_file}
**Affected Function:** {finding.affected_function}

## Description

{finding.description}

## Proof of Concept

```python
{finding.proof_of_concept}
```

## Test Results

- **Verdict:** {finding.test_results.get('verdict', 'N/A')}
- **Output:** {finding.test_results.get('output', 'N/A')[:500]}
- **Elapsed:** {finding.test_results.get('elapsed_s', 0):.2f}s

## Suggested GitHub Issue Title

`[Security] {finding.title} ({finding.cwe})`

## Suggested MITRE CVE Description

{repo_name} through the latest version is vulnerable to {finding.category.value}. \
{finding.test_results.get('output', '').split('VULNERABLE:')[1].strip()[:200] if 'VULNERABLE:' in finding.test_results.get('output', '') else finding.description[:200]}

## Timeline

- **{datetime.now().strftime('%Y-%m-%d')}:** Vulnerability discovered and dynamically verified
- **Discovered by:** Frédéric Bogaerts, University of Coimbra (VAITP Research Project)
"""
        reports.append(report)

    return reports


def main():
    parser = argparse.ArgumentParser(
        description="VAITP Zero-Day Discovery: Scan a repository for vulnerabilities"
    )
    parser.add_argument("repo", help="Git URL or local path to scan")
    parser.add_argument("--model", default="deepseek-r1:14b", help="Ollama model to use")
    parser.add_argument("--max-surfaces", type=int, default=20,
                        help="Max attack surfaces to analyze")
    parser.add_argument("--max-hypotheses", type=int, default=10,
                        help="Max hypotheses to generate and test")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Timeout per test in seconds")
    parser.add_argument("--output", default=None,
                        help="Output JSON path (default: results/discovery_<repo>.json)")

    # Mode flags
    parser.add_argument("--surface-only", action="store_true",
                        help="Only map attack surface, skip all testing")
    parser.add_argument("--llm-only", action="store_true",
                        help="Skip built-in static tests, use only LLM-generated hypotheses")
    parser.add_argument("--taint", action="store_true",
                        help="Run taint analysis (source-to-sink data flow tracking)")

    # Enhancement flags
    parser.add_argument("--llm-review", action="store_true",
                        help="Use LLM to review and assess findings after testing")
    parser.add_argument("--generate-disclosure", action="store_true",
                        help="Generate disclosure reports for confirmed findings")
    parser.add_argument("--voting-config", type=str, default=None,
                        help="Path to a YAML config with a 'voting:' block. Enables the "
                             "jury for allowlisted Phase 0 decisions "
                             "(phase0.hypothesis, phase0.severity).")

    args = parser.parse_args()

    # Determine repo path
    repo_url = args.repo if args.repo.startswith("http") else ""
    if args.repo.startswith("http") or args.repo.startswith("git@"):
        repo_path = clone_repo(args.repo)
    else:
        repo_path = os.path.abspath(args.repo)
        if not os.path.isdir(repo_path):
            logger.error(f"Path does not exist: {repo_path}")
            sys.exit(1)

    repo_name = os.path.basename(repo_path)

    # Output path
    if args.output is None:
        args.output = f"results/discovery_{repo_name}.json"

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  VAITP Zero-Day Discovery Pipeline                         ║
║  Target: {repo_name:<50} ║
║  Model:  {args.model:<50} ║
║  Modes:  {'LLM-only' if args.llm_only else 'Built-in + LLM':<50} ║
╚══════════════════════════════════════════════════════════════╝
""")

    from orchestration.discovery_agent import (
        DiscoveryAgent, map_attack_surface, _detect_module_name
    )

    # ── Surface-only mode ──
    if args.surface_only:
        surfaces = map_attack_surface(repo_path)
        print(f"\nFound {len(surfaces)} security-relevant locations:\n")
        for i, s in enumerate(surfaces[:30], 1):
            print(f"  {i:2d}. [{s.category.value:<20}] {s.file_path}:{s.function_name} "
                  f"(line {s.line_number}, confidence={s.confidence:.2f})")

        if args.taint:
            print(f"\n{'─' * 60}")
            print("TAINT ANALYSIS: Source-to-Sink Data Flows")
            print(f"{'─' * 60}\n")
            from orchestration.taint_tracker import analyze_taint_flows, format_taint_flows
            flows = analyze_taint_flows(repo_path)
            print(f"Found {len(flows)} potential taint flows:\n")
            print(format_taint_flows(flows))
        return

    # ── Taint analysis (standalone) ──
    if args.taint:
        print(f"{'─' * 60}")
        print("TAINT ANALYSIS: Source-to-Sink Data Flows")
        print(f"{'─' * 60}\n")
        from orchestration.taint_tracker import analyze_taint_flows, format_taint_flows
        flows = analyze_taint_flows(repo_path)
        print(f"Found {len(flows)} potential taint flows:\n")
        print(format_taint_flows(flows))
        print()

    # ── Full discovery pipeline ──
    llm_fn = create_ollama_fn(args.model)

    # Optional jury (multi-model voting) for allowlisted Phase 0 decisions.
    jury = None
    hypothesis_fn = llm_fn
    review_fn = llm_fn
    if getattr(args, "voting_config", None):
        from orchestration.voting_jury import load_voting_config, build_jury
        vote_cfg = load_voting_config(args.voting_config)
        jury = build_jury(vote_cfg, tracer=None)
        if jury is not None:
            logger.info(f"Jury enabled: jurors={jury.juror_ids}, "
                        f"decisions={list(vote_cfg.decisions.keys())}")
            hypothesis_fn = jury.make_fn("phase0.hypothesis")
            review_fn = jury.make_fn("phase0.severity")
        else:
            logger.warning("--voting-config provided but voting is disabled/empty; "
                           "using single model.")

    # Dummy LLM for non-LLM modes
    def dummy_llm(prompt, max_tokens=2048, **kwargs):
        return ""

    agent = DiscoveryAgent(
        repo_path=repo_path,
        llm_fn=hypothesis_fn if not args.llm_only else hypothesis_fn,
        python_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv", "bin", "python3"),
        max_surfaces=args.max_surfaces,
        max_hypotheses=args.max_hypotheses if not args.llm_only else args.max_hypotheses,
        test_timeout=args.timeout,
        skip_builtin=args.llm_only,
    )

    findings = agent.run()

    # ── LLM Review ──
    if args.llm_review and findings:
        print(f"\n{'─' * 60}")
        print("LLM REVIEW: Assessing findings...")
        print(f"{'─' * 60}\n")
        findings = llm_review_findings(findings, review_fn, repo_name)
        # Update agent findings
        agent.findings = findings

    agent.save_results(args.output)

    # ── Generate Disclosure ──
    if args.generate_disclosure and findings:
        print(f"\n{'─' * 60}")
        print("DISCLOSURE GENERATION")
        print(f"{'─' * 60}\n")
        reports = generate_disclosure_report(findings, repo_name, repo_url)
        if reports:
            disclosure_dir = f"results/disclosures_{repo_name}"
            os.makedirs(disclosure_dir, exist_ok=True)
            for i, report in enumerate(reports):
                path = os.path.join(disclosure_dir, f"finding_{i+1}.md")
                with open(path, "w") as f:
                    f.write(report)
                print(f"  Disclosure report saved: {path}")
        else:
            print("  No confirmed findings to generate disclosures for.")

    # ── Summary ──
    print(f"\n{'═' * 60}")
    print(f"DISCOVERY COMPLETE")
    print(f"{'═' * 60}")
    print(f"  Findings: {len(findings)}")
    for f in findings:
        status = "🚨 CONFIRMED" if f.confirmed else "⚠️  SUSPECTED"
        print(f"  {status} [{f.category.value}] {f.title[:60]}")
        print(f"           File: {f.affected_file}:{f.affected_function}")
        print(f"           Severity: {f.severity} | CWE: {f.cwe}")
    print(f"\n  Results: {args.output}")


if __name__ == "__main__":
    main()
