"""
Execution Trace Report Generator for VAITP Framework

Collects execution events throughout a run and produces an HTML report
showing the full execution flow with configurable detail levels.
Full prompts and responses are preserved for audit/explainability.

Usage:
    from trace_diagram import get_tracer
    tracer = get_tracer()
    tracer.trace_phase_start("Phase 1", {"model": "deepseek-r1:14b"})
    tracer.trace_llm_call("deepseek-r1:14b", "Identify vulnerability", prompt="...")
    tracer.trace_llm_response("deepseek-r1:14b", "CWE-89 SQL Injection", response="...", duration=2.3)
    ...
    tracer.render("results/my_experiment_trace")
"""

import os
import time
import logging
import json
import html as html_mod
from enum import Enum
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)


class DetailLevel(Enum):
    """Controls how much information is included in the report."""
    MINIMAL = "minimal"      # Phase transitions and final outcomes only
    STANDARD = "standard"    # + LLM call summaries, RAG hits, analysis verdicts
    DETAILED = "detailed"    # + Prompt/response previews, timing, scores
    FULL = "full"            # + Complete prompts and responses


@dataclass
class TraceEvent:
    """A single traced event in the execution."""
    timestamp: float
    event_type: str
    source: str
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    duration: Optional[float] = None
    phase: Optional[str] = None


class ExecutionTracer:
    """
    Collects execution events and renders them as an HTML report.
    When disabled, all trace methods are no-ops with negligible overhead.
    """

    def __init__(self, enabled: bool = False, detail_level: str = "standard",
                 output_dir: str = "results"):
        self.enabled = enabled
        self.detail_level = DetailLevel(detail_level)
        self.output_dir = output_dir
        self.events: List[TraceEvent] = []
        self._start_time = time.time()
        self._current_phase: Optional[str] = None
        self._experiment_name: Optional[str] = None
        self._phase3_will_render = False

    # ------------------------------------------------------------------
    # Trace collection methods
    # ------------------------------------------------------------------

    def trace_config_loaded(self, config: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        self._experiment_name = config.get('experiment_name', 'unnamed')
        summary_fields = {k: config.get(k) for k in (
            'experiment_name', 'phase', 'reasoning_model', 'coders_to_run',
            'strategies_to_run', 'ollama', 'vertex', 'input_dataset_dir',
        )}
        self._add_event("config_loaded", "Config",
                        f"Loaded config: {config.get('experiment_name', '?')}",
                        details={'config_summary': summary_fields,
                                 'full_config': config})

    def trace_resource_detect(self, profile: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        self._add_event("resource_detect", "ResourceManager",
                        f"RAM={profile.get('total_memory_gb', '?')}GB, "
                        f"MPS={profile.get('has_mps', '?')}, CUDA={profile.get('has_cuda', '?')}",
                        details=profile)

    def trace_phase_start(self, phase_name: str, context: Optional[Dict[str, Any]] = None) -> None:
        if not self.enabled:
            return
        self._current_phase = phase_name
        self._add_event("phase_start", "Orchestrator", f"Start {phase_name}",
                        details=context or {}, phase=phase_name)

    def trace_phase_end(self, phase_name: str, summary: Optional[Dict[str, Any]] = None) -> None:
        if not self.enabled:
            return
        self._add_event("phase_end", "Orchestrator", f"End {phase_name}",
                        details=summary or {}, phase=phase_name)
        self._current_phase = None

    def trace_llm_call(self, model: str, purpose: str, prompt: Optional[str] = None,
                       strategy: Optional[str] = None, file_name: Optional[str] = None) -> None:
        if not self.enabled:
            return
        details: Dict[str, Any] = {'model': model, 'purpose': purpose}
        if strategy:
            details['strategy'] = strategy
        if file_name:
            details['file'] = file_name
        if prompt is not None:
            details['prompt'] = prompt
            details['prompt_length'] = len(prompt)
        self._add_event("llm_call", "LLM", f"→ {model}: {purpose}",
                        details=details, phase=self._current_phase)

    def trace_llm_response(self, model: str, summary: str, response: Optional[str] = None,
                           duration: Optional[float] = None, tokens: Optional[int] = None) -> None:
        if not self.enabled:
            return
        details: Dict[str, Any] = {'model': model, 'summary': summary}
        if duration is not None:
            details['duration_s'] = round(duration, 2)
        if tokens is not None:
            details['tokens'] = tokens
        if response is not None:
            details['response'] = response
            details['response_length'] = len(response)
        self._add_event("llm_response", "LLM", f"← {model}: {summary}",
                        details=details, duration=duration, phase=self._current_phase)

    def trace_rag_query(self, query_summary: str, num_results: int,
                        context_size: Optional[int] = None,
                        context: Optional[str] = None) -> None:
        if not self.enabled:
            return
        details: Dict[str, Any] = {'num_results': num_results}
        if context_size is not None:
            details['context_size_chars'] = context_size
        if context is not None:
            details['context'] = context
        self._add_event("rag_query", "RAG", f"RAG: {query_summary} → {num_results} results",
                        details=details, phase=self._current_phase)

    def trace_analysis(self, analysis_type: str, file_name: str,
                       findings: Optional[Dict[str, Any]] = None) -> None:
        if not self.enabled:
            return
        summary = f"{analysis_type} on {file_name}"
        if findings and findings.get('verdict'):
            summary += f" ({findings['verdict']})"
        self._add_event("analysis", "Analysis", summary,
                        details=findings or {}, phase=self._current_phase)

    def trace_docker_exec(self, action: str, file_name: str,
                          result: Optional[Dict[str, Any]] = None,
                          duration: Optional[float] = None) -> None:
        if not self.enabled:
            return
        self._add_event("docker_exec", "Docker", f"Docker {action}: {file_name}",
                        details=result or {}, duration=duration, phase=self._current_phase)

    def trace_error(self, source: str, message: str,
                    details: Optional[Dict[str, Any]] = None) -> None:
        if not self.enabled:
            return
        self._add_event("error", source, f"ERROR: {message}",
                        details=details or {}, phase=self._current_phase)

    def trace_info(self, source: str, message: str,
                   details: Optional[Dict[str, Any]] = None) -> None:
        if not self.enabled:
            return
        self._add_event("info", source, message,
                        details=details or {}, phase=self._current_phase)

    def trace_vote(self, decision: str, strategy: str,
                   jurors: List[Dict[str, Any]], tally: Dict[str, Any],
                   verdict: str, judge_reason: str = "",
                   duration: Optional[float] = None) -> None:
        """Record a jury voting decision (jurors + judge -> verdict)."""
        if not self.enabled:
            return
        n_ok = sum(1 for j in jurors if j.get("ok"))
        summary = f"Vote [{decision}] via {strategy}: {n_ok}/{len(jurors)} jurors"
        if tally:
            summary += f" tally={tally}"
        self._add_event("vote", "Jury", summary,
                        details={
                            "decision": decision,
                            "strategy": strategy,
                            "jurors": jurors,
                            "tally": tally,
                            "judge_reason": judge_reason,
                            "verdict": verdict,
                        },
                        duration=duration, phase=self._current_phase)

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def render(self, output_base_path: Optional[str] = None) -> Optional[str]:
        """Render collected events to an HTML report.

        Returns path to the .html file, or None if tracing is disabled.
        """
        if not self.enabled or not self.events:
            return None

        if output_base_path is None:
            name = self._experiment_name or "unnamed"
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_base_path = os.path.join(self.output_dir, f"{name}_trace_{ts}")

        os.makedirs(os.path.dirname(output_base_path) or '.', exist_ok=True)

        html_path = output_base_path + ".html"
        self._render_html_report(html_path)
        logger.info(f"Trace report saved to: {html_path}")
        return html_path

    def _render_html_report(self, html_path: str) -> None:
        """Render the full HTML execution trace report."""
        experiment_name = self._experiment_name or "unnamed"
        total_duration = self.events[-1].timestamp - self._start_time if self.events else 0

        config_ev = self._find_event("config_loaded")

        lines = []
        lines.append('<!DOCTYPE html>')
        lines.append('<html lang="en"><head><meta charset="utf-8">')
        lines.append(f'<title>Execution Trace: {html_mod.escape(experiment_name)}</title>')
        lines.append(f'<style>{self._get_css()}</style>')
        lines.append('</head><body>')

        # Header
        lines.append(f'<h1>Execution Trace: {html_mod.escape(experiment_name)}</h1>')
        lines.append(f'<p class="meta">Generated: {datetime.now().isoformat()} &middot; '
                     f'Detail level: {self.detail_level.value} &middot; '
                     f'Events: {len(self.events)} &middot; '
                     f'Duration: {total_duration:.1f}s</p>')

        # Configuration
        lines.append('<div class="section">')
        lines.append('<h2>Invocation &amp; Configuration</h2>')
        if config_ev:
            full_cfg = config_ev.details.get('full_config')
            cmd_line = full_cfg.get('_command_line', '') if full_cfg else ''
            if cmd_line:
                lines.append(f'<pre class="command">$ {html_mod.escape(cmd_line)}</pre>')
            if full_cfg:
                # Show config without internal fields
                display_cfg = {k: v for k, v in full_cfg.items() if not k.startswith('_')}
                lines.append('<details open><summary>Full Configuration</summary>')
                lines.append(f'<pre class="config">{html_mod.escape(json.dumps(display_cfg, indent=2, default=str))}</pre>')
                lines.append('</details>')
        lines.append('</div>')

        # Timeline
        lines.append('<div class="section">')
        lines.append('<h2>Detailed Execution Timeline</h2>')

        current_phase = None
        for ev in self.events:
            if ev.event_type == "phase_start":
                if current_phase:
                    lines.append('</div>')
                css = self._phase_css_class(ev.phase or "")
                lines.append(f'<div class="phase {css}">')
                lines.append(f'<h3>{html_mod.escape(ev.summary)}</h3>')
                # Show phase context (model, strategies, etc.)
                if ev.details:
                    ctx_parts = []
                    for k, v in ev.details.items():
                        if v is not None:
                            ctx_parts.append(f'<span class="label">{html_mod.escape(k)}:</span> {html_mod.escape(str(v))}')
                    if ctx_parts:
                        lines.append(f'<div class="phase-context">{" &middot; ".join(ctx_parts)}</div>')
                current_phase = ev.phase
                continue
            elif ev.event_type == "phase_end":
                if ev.details:
                    lines.append(f'<div class="phase-summary">{html_mod.escape(json.dumps(ev.details, default=str))}</div>')
                lines.append('</div>')
                current_phase = None
                continue

            elapsed = ev.timestamp - self._start_time
            css = ev.event_type
            lines.append(f'<div class="event {css}">')
            lines.append(f'<div class="event-header">')
            lines.append(f'<span class="event-type">{html_mod.escape(ev.event_type)}</span>')
            lines.append(f'<span class="event-time">+{elapsed:.1f}s')
            if ev.duration is not None:
                lines.append(f' (took {ev.duration:.1f}s)')
            lines.append('</span></div>')
            lines.append(f'<div class="event-summary">{html_mod.escape(ev.summary)}</div>')

            d = ev.details
            self._render_event_details(lines, ev.event_type, d)
            lines.append('</div>')

        if current_phase:
            lines.append('</div>')
        lines.append('</div>')
        lines.append('</body></html>')

        with open(html_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

    def _render_event_details(self, lines: list, event_type: str, d: Dict[str, Any]) -> None:
        """Append HTML for event-specific details."""
        if event_type == "llm_call":
            for key, label in [('model', 'Model'), ('strategy', 'Strategy'), ('file', 'File')]:
                if d.get(key):
                    lines.append(f'<div class="detail-row"><span class="label">{label}:</span> {html_mod.escape(str(d[key]))}</div>')
            prompt = d.get('prompt', '')
            if prompt:
                lines.append(f'<details><summary>Full Prompt ({len(prompt)} chars)</summary>')
                lines.append(f'<pre class="prompt">{html_mod.escape(prompt)}</pre></details>')

        elif event_type == "llm_response":
            if d.get('model'):
                lines.append(f'<div class="detail-row"><span class="label">Model:</span> {html_mod.escape(str(d["model"]))}</div>')
            if d.get('tokens'):
                lines.append(f'<div class="detail-row"><span class="label">Tokens:</span> {d["tokens"]}</div>')
            response = d.get('response', '')
            if response:
                lines.append(f'<details><summary>Full Response ({len(response)} chars)</summary>')
                lines.append(f'<pre class="response">{html_mod.escape(response)}</pre></details>')

        elif event_type == "rag_query":
            if d.get('num_results') is not None:
                lines.append(f'<div class="detail-row"><span class="label">Results:</span> {d["num_results"]}</div>')
            if d.get('context_size_chars'):
                lines.append(f'<div class="detail-row"><span class="label">Context size:</span> {d["context_size_chars"]} chars</div>')
            ctx = d.get('context', '')
            if ctx:
                lines.append(f'<details><summary>RAG Context ({len(ctx)} chars)</summary>')
                lines.append(f'<pre class="rag-context">{html_mod.escape(ctx)}</pre></details>')

        elif event_type == "analysis":
            if d.get('verdict'):
                lines.append(f'<div class="detail-row"><span class="label">Verdict:</span> <strong>{html_mod.escape(str(d["verdict"]))}</strong></div>')
            if d.get('justification'):
                lines.append(f'<div class="detail-row"><span class="label">Justification:</span> {html_mod.escape(str(d["justification"]))}</div>')
            for key, label in [('model', 'Model'), ('strategy', 'Strategy')]:
                if d.get(key):
                    lines.append(f'<div class="detail-row"><span class="label">{label}:</span> {html_mod.escape(str(d[key]))}</div>')
            for key, label in [
                ('bandit_findings', 'Bandit findings'),
                ('semgrep_findings', 'Semgrep findings'),
                ('devaic_findings', 'DeVAIC findings'),
            ]:
                val = d.get(key)
                if val:
                    # Clean up tool outputs for readability
                    if key == 'semgrep_findings' and isinstance(val, dict):
                        # Only show results and errors, skip timing metadata
                        val = {k: v for k, v in val.items() if k in ('results', 'errors', 'version')}
                        if not val.get('results') and not val.get('errors'):
                            val['summary'] = 'No findings'
                    if key == 'devaic_findings' and isinstance(val, dict):
                        # Strip ANSI codes from raw_output
                        import re as _re
                        raw = val.get('raw_output', '')
                        if raw:
                            val = dict(val)
                            val['raw_output'] = _re.sub(r'\x1b\[[0-9;]*m', '', raw)
                    val_str = json.dumps(val, indent=2, default=str) if isinstance(val, (dict, list)) else str(val)
                    lines.append(f'<details><summary>{label} ({len(val_str)} chars)</summary>')
                    lines.append(f'<pre class="tool-output">{html_mod.escape(val_str)}</pre></details>')

        elif event_type == "docker_exec":
            if d.get('verdict'):
                vc = "pass" if d['verdict'] == "PASS" else "fail"
                lines.append(f'<div class="detail-row verdict-{vc}"><span class="label">Verdict:</span> {html_mod.escape(str(d["verdict"]))}</div>')
            if d.get('iteration'):
                lines.append(f'<div class="detail-row"><span class="label">Iteration:</span> {d["iteration"]}</div>')
            if d.get('command'):
                lines.append(f'<div class="detail-row"><span class="label">Command:</span></div>')
                lines.append(f'<pre class="command">{html_mod.escape(str(d["command"]))}</pre>')
            if d.get('strategy'):
                lines.append(f'<div class="detail-row"><span class="label">Strategy:</span> {html_mod.escape(str(d["strategy"]))}</div>')
            if d.get('payload'):
                lines.append(f'<details><summary>Payload ({len(str(d["payload"]))} chars)</summary>')
                lines.append(f'<pre class="prompt">{html_mod.escape(str(d["payload"]))}</pre></details>')
            if d.get('input'):
                lines.append(f'<div class="detail-row"><span class="label">Input:</span> {html_mod.escape(str(d["input"])[:300])}</div>')
            if d.get('expected'):
                lines.append(f'<div class="detail-row"><span class="label">Expected:</span> {html_mod.escape(str(d["expected"]))}</div>')
            if d.get('success_file'):
                lines.append(f'<div class="detail-row"><span class="label">Success file:</span> {html_mod.escape(str(d["success_file"]))}</div>')
            if d.get('reasons'):
                lines.append(f'<div class="detail-row"><span class="label">Failure reasons:</span> {html_mod.escape(", ".join(str(r) for r in d["reasons"]))}</div>')
            if d.get('output'):
                lines.append(f'<details><summary>Output ({len(str(d["output"]))} chars)</summary>')
                lines.append(f'<pre class="response">{html_mod.escape(str(d["output"]))}</pre></details>')
            # Show verification details from run_with_planner
            for key, label in [
                ('vuln_functional_output', 'Vuln functional output'),
                ('vuln_exploit_output', 'Vuln exploit output'),
                ('vuln_exploit_exploited', 'Vuln exploit triggered'),
                ('vuln_functional', 'Vuln functional'),
                ('vuln_exploit', 'Vuln exploit'),
                ('patch_functional_output', 'Patch functional output'),
                ('patch_exploit_output', 'Patch exploit output'),
                ('patch_functional', 'Patch functional'),
                ('patch_exploit', 'Patch exploit'),
            ]:
                if d.get(key) is not None:
                    val = str(d[key])
                    if len(val) > 200:
                        lines.append(f'<details><summary>{label} ({len(val)} chars)</summary>')
                        lines.append(f'<pre>{html_mod.escape(val)}</pre></details>')
                    else:
                        lines.append(f'<div class="detail-row"><span class="label">{label}:</span> {html_mod.escape(val)}</div>')

        elif event_type == "vote":
            for key, label in [('decision', 'Decision'), ('strategy', 'Strategy'),
                               ('judge_reason', 'Judge')]:
                if d.get(key):
                    lines.append(f'<div class="detail-row"><span class="label">{label}:</span> {html_mod.escape(str(d[key]))}</div>')
            if d.get('tally'):
                lines.append(f'<div class="detail-row"><span class="label">Tally:</span> {html_mod.escape(json.dumps(d["tally"], default=str))}</div>')
            jurors = d.get('jurors') or []
            if jurors:
                lines.append('<details><summary>Juror answers</summary>')
                for j in jurors:
                    jid = html_mod.escape(str(j.get('id', '?')))
                    if j.get('ok'):
                        lab = j.get('label')
                        head = f"{jid}" + (f" → {html_mod.escape(str(lab))}" if lab is not None else "")
                        ans = html_mod.escape(str(j.get('answer', ''))[:2000])
                        lines.append(f'<div class="detail-row"><span class="label">{head}:</span></div>')
                        lines.append(f'<pre class="response">{ans}</pre>')
                    else:
                        lines.append(f'<div class="detail-row"><span class="label">{jid}:</span> ERROR {html_mod.escape(str(j.get("error", "")))}</div>')
                lines.append('</details>')
            if d.get('verdict'):
                lines.append(f'<details><summary>Verdict</summary><pre class="response">{html_mod.escape(str(d["verdict"])[:4000])}</pre></details>')

        elif event_type == "error":
            if d:
                lines.append(f'<pre class="error-detail tool-output">{html_mod.escape(json.dumps(d, indent=2, default=str))}</pre>')

        elif d and d != {}:
            show = {k: v for k, v in d.items() if v is not None and k != 'full_config'}
            if show:
                lines.append(f'<details><summary>Details</summary>')
                lines.append(f'<pre class="tool-output">{html_mod.escape(json.dumps(show, indent=2, default=str))}</pre></details>')

    @staticmethod
    def _get_css() -> str:
        return """
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       max-width: 1200px; margin: 0 auto; padding: 20px; background: #fafafa; color: #333; }
h1 { border-bottom: 3px solid #2196f3; padding-bottom: 10px; }
h2 { color: #1565c0; margin-top: 30px; }
h3 { margin: 0; padding: 8px 0; }
.meta { color: #666; font-size: 0.9em; }
.section { margin: 20px 0; }
.config { background: #263238; color: #aed581; padding: 15px; border-radius: 6px;
          overflow-x: auto; font-size: 0.85em; white-space: pre-wrap; word-break: break-word; }
.command { background: #1a1a2e; color: #e0e0e0; padding: 12px 15px; border-radius: 6px;
           font-size: 0.9em; margin-bottom: 10px; font-family: 'SF Mono', Monaco, monospace; }
.phase { border-left: 4px solid #999; margin: 15px 0; padding: 10px 15px; border-radius: 4px; }
.phase.phase-1 { border-color: #4caf50; background: #e8f5e9; }
.phase.phase-1 h3 { color: #2e7d32; }
.phase.phase-2 { border-color: #2196f3; background: #e3f2fd; }
.phase.phase-2 h3 { color: #1565c0; }
.phase.phase-3 { border-color: #ff9800; background: #fff3e0; }
.phase.phase-3 h3 { color: #e65100; }
.phase.phase-promote { border-color: #9c27b0; background: #f3e5f5; }
.phase.phase-promote h3 { color: #6a1b9a; }
.phase.phase-setup { border-color: #607d8b; background: #eceff1; }
.phase.phase-setup h3 { color: #37474f; }
.phase-summary { font-size: 0.85em; color: #666; margin-top: 8px; font-style: italic; }
.phase-context { font-size: 0.85em; color: #555; margin: 4px 0 8px 0; }
.event { background: #fff; border: 1px solid #e0e0e0; border-radius: 6px;
         margin: 8px 0; padding: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
.event.llm_call { border-left: 4px solid #ff7043; }
.event.llm_response { border-left: 4px solid #66bb6a; }
.event.rag_query { border-left: 4px solid #ab47bc; }
.event.analysis { border-left: 4px solid #42a5f5; }
.event.docker_exec { border-left: 4px solid #ffa726; }
.event.error { border-left: 4px solid #ef5350; background: #ffebee; }
.event.info { border-left: 4px solid #78909c; }
.event.config_loaded { border-left: 4px solid #26a69a; }
.event-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
.event-type { background: #e0e0e0; padding: 2px 8px; border-radius: 3px; font-size: 0.75em;
              font-weight: 600; text-transform: uppercase; }
.event-time { color: #999; font-size: 0.8em; font-family: monospace; }
.event-summary { font-weight: 500; margin-bottom: 8px; }
.detail-row { font-size: 0.9em; margin: 3px 0; overflow-wrap: break-word; word-break: break-word; }
.label { color: #666; font-weight: 600; }
details { margin: 6px 0; }
details summary { cursor: pointer; color: #1565c0; font-size: 0.9em; font-weight: 500; }
details summary:hover { text-decoration: underline; }
pre.prompt { background: #fff3e0; border: 1px solid #ffe0b2; padding: 12px; border-radius: 4px;
             overflow-x: auto; font-size: 0.82em; white-space: pre-wrap; word-break: break-word; max-height: 600px; overflow-y: auto; }
pre.response { background: #e8f5e9; border: 1px solid #c8e6c9; padding: 12px; border-radius: 4px;
               overflow-x: auto; font-size: 0.82em; white-space: pre-wrap; word-break: break-word; max-height: 600px; overflow-y: auto; }
pre.rag-context { background: #f3e5f5; border: 1px solid #e1bee7; padding: 12px; border-radius: 4px;
                  overflow-x: auto; font-size: 0.82em; white-space: pre-wrap; word-break: break-word; max-height: 400px; overflow-y: auto; }
pre.error-detail { background: #ffebee; border: 1px solid #ffcdd2; padding: 10px; border-radius: 4px;
                   font-size: 0.82em; white-space: pre-wrap; }
pre.tool-output { background: #eceff1; border: 1px solid #cfd8dc; padding: 12px; border-radius: 4px;
                  overflow-x: auto; font-size: 0.82em; white-space: pre-wrap; word-break: break-word; max-height: 500px; overflow-y: auto; }
.verdict-pass { color: #2e7d32; font-weight: bold; }
.verdict-fail { color: #c62828; font-weight: bold; }
"""

    @staticmethod
    def _phase_css_class(phase_name: str) -> str:
        p = phase_name.lower()
        if "1" in p: return "phase-1"
        if "2" in p: return "phase-2"
        if "3" in p: return "phase-3"
        if "promot" in p: return "phase-promote"
        return "phase-setup"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add_event(self, event_type: str, source: str, summary: str,
                   details: Optional[Dict[str, Any]] = None,
                   duration: Optional[float] = None,
                   phase: Optional[str] = None) -> None:
        self.events.append(TraceEvent(
            timestamp=time.time(), event_type=event_type, source=source,
            summary=summary, details=details or {},
            duration=duration, phase=phase or self._current_phase,
        ))

    def save_events(self, path: str) -> None:
        """Serialize events to JSON so a subprocess can load and extend them."""
        data = {
            'start_time': self._start_time,
            'experiment_name': self._experiment_name,
            'detail_level': self.detail_level.value,
            'output_dir': self.output_dir,
            'events': [
                {'timestamp': ev.timestamp, 'event_type': ev.event_type,
                 'source': ev.source, 'summary': ev.summary,
                 'details': ev.details, 'duration': ev.duration, 'phase': ev.phase}
                for ev in self.events
            ],
        }
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, default=str)

    def load_events(self, path: str) -> None:
        """Load events from JSON (written by parent process) and prepend them."""
        if not os.path.exists(path):
            return
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self._start_time = data.get('start_time', self._start_time)
        self._experiment_name = self._experiment_name or data.get('experiment_name')
        loaded = [
            TraceEvent(
                timestamp=e['timestamp'], event_type=e['event_type'],
                source=e['source'], summary=e['summary'],
                details=e.get('details', {}), duration=e.get('duration'),
                phase=e.get('phase'),
            )
            for e in data.get('events', [])
        ]
        self.events = loaded + self.events

    def _find_event(self, event_type: str) -> Optional[TraceEvent]:
        for ev in self.events:
            if ev.event_type == event_type:
                return ev
        return None


# ------------------------------------------------------------------
# Module-level singleton
# ------------------------------------------------------------------

_tracer: Optional[ExecutionTracer] = None


def init_tracer(enabled: bool = False, detail_level: str = "standard",
                output_dir: str = "results", **_kwargs) -> ExecutionTracer:
    """Initialize the global tracer singleton. Extra kwargs are ignored for compatibility."""
    global _tracer
    _tracer = ExecutionTracer(enabled=enabled, detail_level=detail_level, output_dir=output_dir)
    return _tracer


def get_tracer() -> ExecutionTracer:
    """Get the global tracer. Returns a disabled tracer if not initialized."""
    global _tracer
    if _tracer is None:
        _tracer = ExecutionTracer(enabled=False)
    return _tracer


# ------------------------------------------------------------------
# LLM call wrapper for automatic prompt/response capture
# ------------------------------------------------------------------

def wrap_llm_for_tracing(llm_callable, model_name: str, purpose: str = ""):
    """Wrap an LLM callable to automatically trace every call with full prompts/responses.
    
    Works with both llama-cpp (dict with 'choices') and Ollama wrapper (same format).
    The wrapper is transparent — it returns exactly what the original callable returns.
    
    Args:
        llm_callable: The original LLM function (Llama instance or wrapper)
        model_name: Model name for trace labels
        purpose: Default purpose label (can be overridden per-call)
    
    Returns:
        A wrapped callable that traces every invocation.
    """
    tracer = get_tracer()
    if not tracer.enabled:
        return llm_callable

    class TracingLLMWrapper:
        """Wraps an LLM callable to intercept and trace all calls."""
        
        def __init__(self, original, model, default_purpose):
            self._original = original
            self._model = model
            self._purpose = default_purpose
            self._call_count = 0
            # Copy attributes from original so isinstance checks etc. still work
            for attr in ('n_ctx', 'model_path', 'verbose', 'metadata', '_model'):
                if hasattr(original, attr):
                    try:
                        setattr(self, attr, getattr(original, attr))
                    except (AttributeError, TypeError):
                        pass
        
        def __call__(self, *args, **kwargs):
            self._call_count += 1
            # Extract prompt from args or kwargs
            prompt = None
            if args:
                prompt = args[0]
            elif 'prompt' in kwargs:
                prompt = kwargs['prompt']
            
            label = f"{self._purpose} (call #{self._call_count})"
            tracer.trace_llm_call(self._model, label, prompt=prompt)
            t0 = time.time()
            
            try:
                result = self._original(*args, **kwargs)
                duration = time.time() - t0
                
                # Extract response text
                response_text = ""
                if isinstance(result, dict) and 'choices' in result:
                    choices = result.get('choices', [])
                    if choices and isinstance(choices[0], dict):
                        response_text = choices[0].get('text', '')
                elif isinstance(result, str):
                    response_text = result
                
                tracer.trace_llm_response(
                    self._model,
                    f"Response ({len(response_text)} chars, {duration:.1f}s)",
                    response=response_text,
                    duration=duration,
                )
                return result
                
            except Exception as e:
                duration = time.time() - t0
                tracer.trace_error("LLM", f"{self._model} call failed: {e}")
                raise
        
        def __getattr__(self, name):
            # Proxy all other attribute access to the original
            return getattr(self._original, name)
    
    return TracingLLMWrapper(llm_callable, model_name, purpose)
