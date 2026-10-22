"""
VAITP LLM Stream Display — Markdown log-file mode with ANSI colors.

All LLM prompts and responses are written to llm_stream.log as Markdown,
with ANSI color codes for distinct visual separation when viewed with
`tail -f llm_stream.log` or `cat llm_stream.log` in a terminal.

Color scheme:
  - Phase/call headers: bold cyan
  - Prompts: yellow background
  - Responses: green
  - Metadata (tokens, timing): dim/gray

Usage:
    from llm_stream_display import init_display, get_display, shutdown_display

    init_display()
    display = get_display()
    display.stream_start("generating plan...")
    display.stream_prompt(full_prompt_text)
    display.stream_token("Hello ")
    display.stream_token("world\\n")
    display.stream_end()
    shutdown_display()
"""
import logging
import time
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)

LOG_FILE = "llm_stream.log"

# ANSI color codes for terminal viewing (tail -f / cat)
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_ITALIC = "\033[3m"
_CYAN = "\033[96m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_MAGENTA = "\033[95m"
_RED = "\033[91m"
_BLUE = "\033[94m"
_BG_YELLOW = "\033[43m\033[30m"  # yellow bg, black text
_BG_CYAN = "\033[46m\033[30m"    # cyan bg, black text
_BG_GREEN = "\033[42m\033[30m"   # green bg, black text
_GRAY = "\033[90m"

# Phase-specific colors for easy visual distinction
_PHASE_COLORS = {
    "Phase 1": _MAGENTA,
    "Phase 2": _BLUE,
    "Phase 3": _CYAN,
}


class StreamDisplay:
    """Markdown + ANSI color LLM stream recorder."""

    def __init__(self):
        self._active = False
        self._streaming = False
        self._call_count = 0
        self._current_phase = ""
        self._log_file = None
        self._token_count = 0
        self._start_time = 0.0

    @property
    def active(self) -> bool:
        return self._active

    def start(self, append: bool = False):
        """Open the log file and activate. Truncates unless append=True."""
        self._active = True
        mode = "a" if append else "w"
        try:
            self._log_file = open(LOG_FILE, mode, encoding="utf-8")
            ts = datetime.now().isoformat()
            self._w(f"\n{_BOLD}{_CYAN}{'═' * 80}{_RESET}\n")
            self._w(f"{_BOLD}{_CYAN}# VAITP LLM Stream Log — {ts}{_RESET}\n")
            self._w(f"{_BOLD}{_CYAN}{'═' * 80}{_RESET}\n\n")
            self._flush()
        except Exception as e:
            logger.warning(f"Could not open {LOG_FILE}: {e}")
            self._log_file = None

    def stop(self):
        """Close the log file."""
        self._active = False
        self._streaming = False
        if self._log_file:
            self._log_file.close()
            self._log_file = None

    def set_phase(self, phase: str):
        self._current_phase = phase

    def stream_start(self, label: str = ""):
        if not self._active:
            return
        self._call_count += 1
        self._token_count = 0
        self._start_time = time.time()
        self._streaming = True
        if self._log_file:
            phase_color = _PHASE_COLORS.get(self._current_phase, _CYAN)
            ts = datetime.now().strftime('%H:%M:%S')
            self._w(f"\n{phase_color}{'─' * 80}{_RESET}\n")
            self._w(f"{_BOLD}{phase_color}## [{self._current_phase}] Call #{self._call_count} — {ts}{_RESET}\n")
            if label:
                self._w(f"{_DIM}{phase_color}> {label}{_RESET}\n")
            self._w(f"{phase_color}{'─' * 80}{_RESET}\n")
            self._flush()

    def stream_prompt(self, prompt: str):
        if not self._active or not self._log_file:
            return
        char_count = len(prompt)
        self._w(f"\n{_BOLD}{_YELLOW}### 📤 PROMPT{_RESET} {_DIM}({char_count} chars){_RESET}\n")
        self._w(f"{_YELLOW}```\n")
        self._w(prompt)
        self._w(f"\n```{_RESET}\n")
        self._w(f"\n{_BOLD}{_GREEN}### 📥 RESPONSE{_RESET}\n")
        self._w(f"{_GREEN}")
        self._flush()

    def stream_token(self, token: str):
        if not self._active or not self._streaming:
            return
        self._token_count += 1
        if self._log_file:
            self._log_file.write(token)
            if self._token_count % 50 == 0:
                self._log_file.flush()

    def stream_end(self):
        if not self._active or not self._streaming:
            return
        elapsed = time.time() - self._start_time
        self._streaming = False
        if self._log_file:
            self._w(f"{_RESET}\n")
            self._w(f"\n{_GRAY}---{_RESET}\n")
            self._w(f"{_DIM}📊 {self._token_count} tokens | ⏱ {elapsed:.1f}s | "
                    f"~{self._token_count / max(elapsed, 0.1):.1f} tok/s{_RESET}\n\n")
            self._flush()

    def _w(self, text: str):
        """Write to log file (shorthand)."""
        if self._log_file:
            self._log_file.write(text)

    def _flush(self):
        """Flush log file."""
        if self._log_file:
            self._log_file.flush()


# Module-level singleton
_global_display: Optional[StreamDisplay] = None


def get_display() -> Optional[StreamDisplay]:
    return _global_display


def init_display(append: bool = False) -> StreamDisplay:
    global _global_display
    if _global_display and _global_display.active:
        return _global_display
    _global_display = StreamDisplay()
    _global_display.start(append=append)
    return _global_display


def shutdown_display():
    global _global_display
    if _global_display:
        _global_display.stop()
        _global_display = None
