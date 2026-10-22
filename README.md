# VAITP Framework Documentation

## Overview

**VAITP** (Vulnerability Attack and Injection Tool for Python) is an AI-driven security testing framework that uses Large Language Models to automatically inject vulnerabilities into Python code, generate attack execution plans, and verify that vulnerabilities are exploitable in isolated Docker containers.

The framework operates across four phases:

- **Phase 0** — Zero-Day Discovery: Autonomous vulnerability discovery in real-world repositories using attack surface mapping, taint analysis, built-in checks, and LLM-driven hypothesis testing.
- **Phase 1** — Plan Generation: LLMs analyze code and produce vulnerability injection plans using RAG context.
- **Phase 2** — Code Generation & Analysis: LLMs generate vulnerable code, which is evaluated via static analysis (Bandit, Semgrep, DeVAIC), and similarity metrics (BLEU-4, CodeBLEU, ROUGE-L, Edit Distance).
- **Phase 3** — Autonomous attack execution, Docker-based exploitation, and self-correcting feedback loops driven by LLMs (local or remote via Vertex API).

Phase 3 transforms VAITP from a code injection tool into a **Vulnerability Excploitation Verification Engine** where models autonomously reason about how to exploit vulnerabilities, test their plans, learn from failures, and evolve (learning from past successful and failed attemps). The framework supports both local inference (with Ollama or llama-cpp-python) and remote API endpoints (Vertex AI Model Garden) for model-agnostic experimentation.

## Architecture

```
Phase 1: Plan Generation    Phase 2: Code Generation     Phase 3: Verification Engine
        │                           │                              │
  Meta-Prompts              Vulnerable Code Gen            ┌───────┴────────┐
  RAG Context               Static/Dynamic Analysis        │  Planner Agent │
  Injection Plans           Similarity Metrics             │  (LLM Brain)   │
                                                           └───────┬────────┘
                                                                   │
                                                   SEP + CEP + AEP + FEP Generation
                                                                   │
                                                           ┌───────┴────────┐
                                                           │  Docker Infra  │
                                                           │  Provisioning  │
                                                           └───────┬────────┘
                                                                   │
                                                           ┌───────┴────────┐
                                                           │ Attack Executor│
                                                           │ (Truth Table)  │
                                                           └───────┬────────┘
                                                                   │
                                                              PASS / FAIL
                                                                   │
                                                           ┌───────┴────────┐
                                                           │  Feedback Loop │
                                                           │  (Self-Correct)│
                                                           └────────────────┘
```

## Phase 1: Core Concepts

### Meta-Prompting Pipeline

Phase 1 uses a two-level prompting architecture where a reasoning LLM generates instructions for a coder LLM, rather than generating vulnerable code directly:

1. The **LLMInjectPlannerAgent** receives the target source code, RAG context (similar vulnerability examples retrieved via FAISS [the index is build from vaitp's website db]), and intended vulnerability metadata (type, CWE, expected code pattern).
2. It generates a **7-point task prompt** — a structured instruction list telling the coder LLM exactly what to modify (target function, vulnerability type, code change, validation bypass, observability hooks, minimality constraint, output format).
3. The task prompt includes side-effect guidance specific to the vulnerability type, ensuring the injected vulnerability is provable via file creation in Docker (in phase 3).

### RAG Component

A FAISS-based vector store indexes vulnerability examples from the VAITP knowledge base. For each target file, the top-k (I've tried with different values, atm k is set to 3 as per empirical test results) most similar examples are retrieved and included as context in the planner prompt, grounding the LLM's reasoning in real vulnerability patterns.

### Vulnerability Identification

The **VulnerabilityIdentificationAgent** classifies each target file's vulnerability type by analyzing the code with the reasoning LLM. This classification drives the RAG query and determines the side-effect instrumentation strategy for Phase 3.

Alternatively, the user can specify the intended vulnerability directly in the YAML config via `intended_vulnerability`, bypassing the LLM identification step entirely. This is useful when all input files target the same vulnerability class, or when the user wants deterministic control over the injection type. The parameter accepts either a simple string or a full dict:

```yaml
# Simple form — just the vulnerability type
intended_vulnerability: "SQL Injection"

# Full form — with CWE and expected code pattern
intended_vulnerability:
  type: "SQL Injection"
  cwe: "CWE-89"
  expected_pattern: "cursor.execute(f'SELECT * FROM users WHERE username = \\'{username}\\'')"
```

When set, the `VulnerabilityIdentificationAgent` is not instantiated and no LLM inference is spent on vulnerability classification. The CLI equivalent is `--intended-vulnerability "SQL Injection"`.

## Phase 2: Core Concepts

### Prompting Strategies

Phase 2 evaluates five prompting strategies to measure the impact of meta-prompting and RAG on injection quality:

| Strategy | Description |
|---|---|
| `DIRECT_ONLY` | Direct instruction to the coder LLM without RAG context |
| `DIRECT_RAG` | Direct instruction with RAG-retrieved vulnerability examples |
| `META_ONLY` | Meta-prompt (Phase 1 task prompt) without RAG context |
| `META_RAG` | Meta-prompt with RAG context (the full pipeline) |
| `FEW_SHOT` | Few-shot examples of vulnerable code transformations |

### Code Generation

The **LLMInjectCoderAgent** receives the task prompt from Phase 1 (or a direct instruction) and generates the vulnerable code variant. It wraps prompts in the appropriate chat template (ChatML for Qwen/DeepSeek, Llama3 format for Meta models) and handles context window truncation.

### Static Analysis & Evaluation

Generated code is evaluated through multiple lenses:
- **Static analysis**: Bandit, Semgrep and DeVAIC (DeVAITP modded version of DeVAIC - scans in less than 5 seconds instead of over 1 min) scan for known vulnerability patterns, confirming the injection introduced a detectable flaw.
- **Semantic correctness**: The **DynamicConfirmationAgent** uses the LLM to evaluate whether the static analysis findings match the intended vulnerability.
- **Similarity metrics**: BLEU-4, CodeBLEU, ROUGE-L, and Edit Distance measure how closely the generated code matches expected vulnerable code, ensuring minimal unnecessary changes.

### Sequential Model Processing

Phase 2 processes multiple coder models sequentially with aggressive memory cleanup between models (GPU cache clearing, garbage collection, MPS empty cache on macOS). The **SequentialModelManager** handles model lifecycle to prevent OOM on memory-constrained hardware.

## Phase 3: Core Concepts

### Data Contracts (`structures.py`)

All Phase 3 operations use strict dataclass contracts:

- **SEP (Setup Execution Plan)** — Defines the Docker infrastructure: base image, dependencies, setup commands, sidecar services (e.g., MongoDB), and file mappings.
- **CEP (Common Execution Plan)** — Defines the shared delivery mechanism: strategy (`stdio` or `network`), success file path, HTTP configuration (URL, method, JSON template, headers), exploit rationale, and optional side-effect hooks for vulnerability types that don't naturally produce file-system artifacts.
- **AEP (Attack Execution Plan)** — Defines the malicious payloads: static strings, generator scripts (Python executed inside the container whose stdout becomes the payload), and crafted files written into the container before execution. Each AEP contains multiple payload variants; any single successful try proves exploitability.
- **FEP (Functional Execution Plan)** — Defines benign inputs and expected outputs for functional verification. Optionally includes separate `patch_tries` when the patched code accepts a different input format (e.g., JSON instead of pickle).
- **VerificationReport** — The Truth Table result for a single test, containing functional and exploit results for both vulnerable and patched code.
- **PlannerFeedback** — Actionable feedback sent back to the Planner Agent when a test fails, enabling self-correction. Supports both static rule-based suggestions and LLM-generated context-aware diagnostics.
- **TestVerdict** — `PASS`, `FAIL`, `ERROR`, or `INFRA_FAILURE`.

### Double-Check Methodology (Truth Table)

Every test (in phase 3) must satisfy all four conditions to PASS:

| Code Version | Input Type | Expected Result |
|---|---|---|
| Vulnerable | Benign | Success (functional) |
| Vulnerable | Malicious | Exploited (side-effect file created) |
| Patched | Benign | Success (functional) |
| Patched | Malicious | Blocked (no side-effect) |

If benign input fails on either version, the verdict is `INFRA_FAILURE` (environment problem, not a test failure). Side-effects (file creation via `touch /tmp/pwned_*`) are always used over stdout for exploitation proof.

### Attack Strategies

**STDIO** — For scripts that read from `stdin`. The payload is Base64-encoded before piping to avoid shell escaping issues:
```
echo <base64> | base64 -d | python -u script.py
```

**NETWORK** — For web applications. The executor:
1. Kills any existing Python processes (`pkill -9`)
2. Starts the app in background
3. Waits for startup
4. Sends `curl` requests (GET with URL params, POST with JSON, multipart uploads, header injection, cookie injection)
5. Checks for side-effect file
6. Kills the server

## Phase 3: Components

### Planner Agent (`orchestration/planner_agent.py`)

The "brain" that generates SEP/CEP/AEP/FEP plans from code analysis. Uses a two-step atomic approach:
- Step 1: Generate SEP + CEP (infrastructure + delivery mechanism)
- Step 2: Generate AEP + FEP (payloads + benign tests) given the CEP
- Falls back to single-shot generation if two-step fails
- Keyword-based few-shot example selection from previously proven plans
- JSON extraction with `<think>` token stripping for reasoning models (DeepSeek R1, Qwen3)
- Automatic JSON repair for common LLM output issues (malformed JSON, missing fields)
- Self-correction via `PlannerFeedback` from failed attempts
- Static code analysis hints (detecting shell patterns, SQL methods, deserialization calls) to inform payload construction

### Attack Executor (`orchestration/attack_executor.py`)

Ported from the Ground Truth (`run_all_poc_tests.py`). Handles:
- `run_functional_check()` — Benign input verification
- `run_exploit_check()` — Malicious payload with file-based side-effect detection
- `_prepare_curl()` — Builds curl commands for all network attack patterns (GET params, POST JSON, multipart, headers, cookies with `PAYLOAD_PLACEHOLDER` substitution)
- `_run_stdio()` — Base64 CLI wrapper for safe payload delivery

### Docker Infrastructure (`docker_utils.py`)

- **MultiContainerManager** — Phase 3 multi-container orchestrator with Docker networking, sidecar services, dependency installation, and file copying.
- **DockerNetworkManager** — Creates/manages bridge networks for multi-container test environments.
- **DockerContainerManager** — Legacy single-container manager for Phase 1/2 backward compatibility.

Provisioning flow: Create network → Start sidecars (MongoDB, etc.) → Start target container → Install apt/pip deps → Run setup commands → Copy vuln + patched scripts.

### Phase 3 Orchestrator (`orchestration/phase3_orchestrator.py`)

Coordinates the full verification loop:
- `run_single_test()` — Deterministic path with known SEP/AEP (for regression testing)
- `run_with_planner()` — Self-correction loop: generate plan → test → feedback → retry (up to N iterations)
- `run_regression_suite()` — Batch execution from a test registry
- LLM-driven recovery decisions: fuzz, replan, fix_infra, or abort
- Side-effect hook generation on-the-fly when auto-injection fails
- Exploit failure analysis: LLM traces the payload through the code to identify where it fails
- **Exploit-aware recovery**: When the exploit already succeeded but functional tests failed, the orchestrator short-circuits to `fix_infra` instead of letting the LLM choose `fuzz` (which would waste iterations trying new payloads when the attack already works). The feedback explicitly tells the planner to fix the FEP expected responses rather than the AEP payloads.

### Fuzzer Agent (`orchestration/fuzzer_agent.py`)

Context-aware payload mutator that reads the vulnerable code to understand input parsing logic:
- Generates targeted payload mutations based on code analysis (regex patterns, JSON schemas, split operations)
- Receives feedback from previous failed attempts including LLM-generated failure analysis
- Falls back to rule-based mutations (encoding variants, command separator alternatives, null byte injection)

### Diagnostic Agent (`orchestration/diagnostic_agent.py`)

Automates the critical thinking / debugging loop using a local LLM. Two modes:

**Standard Mode** (`diagnose_and_fix` / `run_diagnostic_suite`):
- Takes pre-written SEP/AEP from the mutation registry
- Runs tests through the Phase 3 orchestrator
- On failure, builds a diagnostic prompt with 5 few-shot examples of real bugs fixed during development
- LLM analyzes root cause and proposes fixes to AEP/SEP fields
- Applies fixes in-memory and re-runs (up to N attempts per test)

**Autonomous Mode** (`reason_from_scratch` / `run_autonomous_suite`):
- No pre-written plans needed
- LLM reads vulnerable + patched code
- Uses the PlannerAgent to generate SEP/AEP entirely from code analysis
- Tests the plan in Docker
- On failure, generates PlannerFeedback and feeds it back to the Planner
- The Planner self-corrects and generates a new plan
- Iterates until PASS or max attempts
- Accumulates successful plans as "learned" examples for future reference

The autonomous mode is the primary vision: local models reason from scratch, test their hypotheses, learn from failures, and evolve into agents that can prove vulnerabilities are exploitable.


## Gold Standard Test Suite

### 20 Gold Standard Vulnerabilities

The Ground Truth is defined in `test_phase3_regression.py` with 20 proven-exploitable test cases:

**STDIO (10):**

| # | File | Vulnerability | CWE/CVE |
|---|---|---|---|
| 1 | `1167_1.py` | OS Command Injection (subprocess, shell=True) | CWE-78 |
| 2 | `360_1.py` | GitPython RCE (ext:: protocol) | CVE-2022-24439 |
| 3 | `yaml_1.py` | YAML Deserialization (yaml.load) | CWE-502 |
| 4 | `sqli_1.py` | SQL Injection (executescript, f-string) | CWE-89 |
| 5 | `eval_1.py` | Eval Injection (eval on user input) | CWE-95 |
| 6 | `ssti_1.py` | SSTI / Jinja2 (render from string) | CWE-1336 |
| 7 | `pickle_1.py` | Pickle Deserialization (pickle.loads) | CWE-502 |
| 8 | `zip_1.py` | Zip Slip Path Traversal (tar extraction) | CWE-22 |
| 9 | `xslt_1.py` | XSLT Injection (lxml, exsl:document) | CWE-91 |
| 10 | `mako_1.py` | Mako Template Injection | CWE-94 |

**NETWORK (10):**

| # | File | Vulnerability | CWE/CVE |
|---|---|---|---|
| 11 | `flask_1.py` | Flask GET RCE (os.system on query param) | CWE-78 |
| 12 | `flask_ssti_1.py` | Flask SSTI (render_template_string) | CWE-1336 |
| 13 | `flask_json_1.py` | Flask JSON POST RCE (os.system on JSON field) | CWE-78 |
| 14 | `flask_upload_1.py` | Flask Upload Path Traversal | CWE-22 |
| 15 | `flask_header_1.py` | Flask Header Injection (os.system on header) | CWE-78 |
| 16 | `flask_pickle_1.py` | Flask Pickle Cookie RCE (pickle.loads on cookie) | CWE-502 |
| 17 | `flask_ssrf_1.py` | Flask SSRF to Internal Admin Endpoint | CWE-918 |
| 18 | `flask_jwt_1.py` | Flask JWT None Algorithm Bypass | CWE-345 |
| 19 | `flask_nosql_1.py` | Flask NoSQL Injection (mock) | CWE-943 |
| 20 | `flask_nosql_real.py` | Flask NoSQL Injection (real MongoDB sidecar) | CWE-943 |

### 60 Mutation Variants

Each of the 20 gold standards has 3 mutations (v2, v3, v4), totaling **60 mutation pairs** (120 files: 60 vulnerable + 60 patched).

Mutations change route names, variable names, application context, and sometimes the vulnerable API pattern — while preserving the same underlying vulnerability logic so the same payload type works.

**STDIO mutations** (30 pairs) are generated by `gold_standard/generate_mutations.py`.
**NETWORK mutations** (30 pairs) are generated by `gold_standard/generate_network_mutations.py`.

All 60 mutations are registered in `gold_standard/mutation_registry.py` with their SEP/AEP configurations.

**Categories (20):**
`subprocess`, `yaml`, `sqli`, `eval`, `ssti`, `pickle`, `mako`, `xslt`, `zip`, `git`, `flask_rce`, `flask_ssti`, `flask_json`, `flask_upload`, `flask_header`, `flask_pickle`, `flask_ssrf`, `flask_jwt`, `flask_nosql`, `flask_nosql_real`

## File Reference

### Phase 3 Core

| File | Purpose |
|---|---|
| `structures.py` | Data contracts: SEP, CEP, AEP, FEP, VerificationReport, PlannerFeedback, TestVerdict |
| `docker_utils.py` | MultiContainerManager + DockerNetworkManager + legacy DockerContainerManager |
| `run_phase3.py` | Standalone Phase 3 runner with `--ollama`, `--vertex`, `--filter`, `--resume` support |
| `vertex_backend.py` | Vertex AI backend: OpenAI-compatible + Anthropic SDK, token refresh, thinking token stripping, fatal error handling |
| `run_vaitp_vertex.sh` | Vertex AI launcher script with gcloud token refresh |
| `orchestration/__init__.py` | Package exports for Phase 3 modules |
| `orchestration/planner_agent.py` | PlannerAgent: two-step SEP/CEP + AEP/FEP generation with `<think>` stripping |
| `orchestration/attack_executor.py` | AttackExecutor: functional + exploit checks, Base64 CLI, curl construction |
| `orchestration/phase3_orchestrator.py` | Phase3Orchestrator: single test, planner loop, LLM recovery decisions |
| `orchestration/diagnostic_agent.py` | DiagnosticAgent: standard + autonomous modes, LLM-driven debugging |
| `orchestration/fuzzer_agent.py` | FuzzerAgent: context-aware payload mutation with LLM + rule-based fallback |
| `orchestration/side_effect_injector.py` | Auto-injects side-effect hooks for vulnerability types without natural file-system artifacts |

### Gold Standard & Mutations

| File | Purpose |
|---|---|
| `gold_standard/__init__.py` | Package init |
| `gold_standard/generate_mutations.py` | Generates 30 STDIO mutation pairs (v2/v3/v4 for 10 categories) |
| `gold_standard/generate_network_mutations.py` | Generates 30 NETWORK mutation pairs (v2/v3/v4 for 10 categories) |
| `gold_standard/mutation_registry.py` | Maps all 60 mutations to SEP/AEP configurations |
| `gold_standard/tools/payload_generators.py` | Runtime payload generators (zip slip, pickle, tar, benign archives) |
| `gold_standard/tools/gen_payload_zip.py` | Standalone zip payload generator |
| `gold_standard/setup/` | 13 original setup files for gold standard test environments |
| `gold_standard/beta_tests/` | 3 beta test files from early Phase 3 development |

### Test Runners

| File | Purpose |
|---|---|
| `test_phase3_regression.py` | Runs the 20 Gold Standard tests (deterministic, no LLM) |
| `test_phase3_mutations.py` | Runs the 60 mutation tests (deterministic, no LLM) |
| `test_phase3_diagnostic.py` | Runs the Diagnostic Agent (standard or autonomous mode, with LLM) |
| `test_phase3_planner_loop.py` | Unit tests for the Planner self-correction loop (MockLLM) |
| `run_all_poc_tests.py` | Original Ground Truth PoC runner (legacy, kept as reference) |

### Phase 1/2 (Existing)

| File | Purpose |
|---|---|
| `main_orchestrator.py` | Primary entry point for Phase 1/2/3 experiments, supports `--config`, `--vertex`, `--ollama` (see --help) |
| `orchestration/orchestrator.py` | Core Phase 1/2 orchestration |
| `orchestration/injection_agents.py` | Vulnerability injection agents (LLMInjectPlannerAgent, LLMInjectCoderAgent) |
| `orchestration/attack_agents.py` | Attack execution plan agents |
| `config.py` | Central configuration: models, paths, settings |
| `model_backends.py` | Abstraction layer for llama-cpp-python, oLLM, and Ollama backends |
| `prompt_templates.py` | Prompting strategies (DIRECT, META, RAG, FEW_SHOT) |
| `code_similarity_evaluator.py` | BLEU-4, CodeBLEU, ROUGE-L, Edit Distance metrics |
| `configuration_manager.py` | YAML config loading, validation, and experiment metadata |

### Infrastructure & Utilities

| File | Purpose |
|---|---|
| `adaptive_resource_manager.py` | Adaptative resource allocation based on hardware |
| `sequential_model_manager.py` | One-model-at-a-time execution with memory cleanup |
| `memory_manager.py` | Memory profiling and optimization |
| `parallel_execution.py` | Multi-GPU parallel execution |
| `performance_optimizer.py` | Performance optimization strategies |
| `resource_checker.py` | GPU/MPS/memory/disk validation |
| `logging_utils.py` | SQLite-based experiment logging |
| `enhanced_logging.py` | Rich console logging |
| `ollm_manager.py` | oLLM backend integration for 70B+ models |
| `ollm_logging.py` | oLLM-specific metrics logging |
| `ollm_metrics_integration.py` | oLLM metrics collection |
| `monitoring_dashboard.py` | Real-time monitoring |
| `utils.py` | Core utilities (payload detection, sanitization, Bandit integration) |

## Supported Models

### Local Models (Ollama / llama-cpp-python) [Configuration can be addapted if hardware support differs from mine] - The framework is model-agnostic and you can configure it with any model that your hardware supports (to run locally).

| Model | Context | Format | Backend | Notes |
|---|---|---|---|---|
| `deepseek-r1:14b` | 8K | ChatML | Ollama | Reasoning model with `<think>` tokens |
| `llama-3.1-8b` | 8K | Llama3 | llama-cpp / Ollama | General-purpose |
| `qwen2.5-coder-3b-abliterated-basic` | 8K | ChatML | llama-cpp / Ollama | Uncensored coder |
| `gemma-3-12b-it-jailbreak` | 8K | ChatML | llama-cpp | Jailbroken variant |

### Vertex AI Models (Remote API via Model Garden) - These are the models I'm currently testing with..

| Model | Model ID | Endpoint | Type | Notes |
|---|---|---|---|---|
| DeepSeek R1-0528 | `deepseek-ai/deepseek-r1-0528-maas` | us-central1 (OpenAI-compat) | Open, Reasoning | `<think>` tokens stripped automatically |
| Gemini 2.5 Pro | `google/gemini-2.5-pro` | us-central1 (OpenAI-compat) | Closed, Reasoning | Native Vertex AI |
| Qwen3-235B | `qwen/qwen3-235b-a22b-instruct-2507-maas` | global (OpenAI-compat) | Open, Reasoning | Hybrid thinking mode |
| Claude Sonnet 4.6 | `anthropic/claude-sonnet-4-6` | global (Anthropic SDK) | Closed, Non-reasoning | Via `AnthropicVertex` client |
| Claude Opus 4.6 | `anthropic/claude-opus-4-6` | global (Anthropic SDK) | Closed, Non-reasoning | Optional, budget permitting |

Vertex AI configs are in `configs/config_*.yaml`. Authentication uses short-lived gcloud access tokens with automatic refresh via `vertex_backend.py`.

#### Vertex AI Authentication Setup

Before running any Vertex AI experiments, authenticate with Google Cloud:

```bash
gcloud auth application-default login
```

This opens a browser for OAuth and stores credentials locally. The framework automatically mints fresh access tokens via `gcloud auth application-default print-access-token` whenever needed (tokens expire after ~1 hour and are refreshed transparently).

> **Note:** Do not rely on the `VERTEX_ACCESS_TOKEN` environment variable — the framework manages tokens internally. If you have it set, unset it: `unset VERTEX_ACCESS_TOKEN`.

### Coder Models (Phase 2)

Base + Fine-tuned variants: Llama-3.1-8B, Llama-3.2-1B, Qwen-2.5-7B, Qwen-3-8B, Qwen-3-1.7B, Codepy-3B.

All GGUF models are stored in `~/models/` and loaded via `llama-cpp-python` with MPS acceleration on macOS.

## Dataset

`vaitp_dataset/` is **not tracked in git** (it is listed in `.gitignore`). The framework does not ship test files: **to use and test it, you add your own vulnerable / patched Python files.**

### Adding your own files

Put each vulnerable file in `vaitp_dataset/vulnerable/` and its patched (safe) counterpart in `vaitp_dataset/injectable/`, **using the same filename in both folders**:

```
vaitp_dataset/
├── vulnerable/
│   └── cwe89_myapp_00_find_user.py    # vulnerable version
└── injectable/
    └── cwe89_myapp_00_find_user.py    # patched (safe) version
```

- `run_phase3.py` tests only files that exist in both folders; a file with no counterpart is skipped.
- Each file should be a complete, runnable program, since Phase 3 runs it in a Docker container and attacks it.
- Start the filename with the CWE (`cwe89_`, `cwe78_`, `cwe22_`, `cwe502_`, `cwe94_`, `cwe79_`, `cwe918_`, `cwe601_`, `cwe352_`, `cwe287_`) to tell Phase 3 which detector to use for that file. Without the prefix, the category is inferred from the code, which is less reliable.
- Phase 1/2 configs read from the folder set in `input_dataset_dir` (and `expected_dir`), and the `Phase-3-vertex-sven-pyvul-*` configs read from `vaitp_dataset/phase3_sven_pyvul/`. Put your files there, or point the config at your own folder.

### Files used in our experiments

The vulnerable / patched files used in our papers are archived on Zenodo with the rest of the paper artifacts: https://doi.org/10.5281/zenodo.19705841 (access on request through Zenodo). To use them, extract them into the folders above.

### Building datasets from public sources (optional)

The repository also contains scripts that build vulnerable / patched sets from public datasets. Run them from the repository root.

**SVEN + PyVul set** (100 pairs, 10 per CWE). This writes `vaitp_dataset/phase3_sven_pyvul/{vulnerable,injectable}/`:

```bash
git clone https://github.com/eth-sri/sven vaitp_dataset/sven
git clone https://github.com/billquan/PyVul.git vaitp_dataset/pyvul
python scripts/build_phase3_sven_pyvul_dataset.py
```

Repair scripts such as `scripts/fix_runtime_issues.py` and `scripts/deep_fix_all_files.py` edit the files after they are built, so a fresh build may not match the files we used. For those, use the Zenodo archive.

**Genuine set** (generated programs with a reachable sink). This writes `vaitp_dataset/phase3_genuine/{vulnerable,injectable}/` and `manifest.json` with benign and exploit inputs per sample:

```bash
python scripts/build_genuine_dataset.py
venv/bin/python scripts/validate_genuine_dataset.py
```

The validator runs every pair against the four double-check conditions. A pair is valid when both versions run the benign input cleanly, the exploit takes effect on the vulnerable version, and the safe version blocks it. Network samples need Flask, so run the validator with the project venv; without Flask they are reported as SKIPPED.

**Older snapshot.** The last commit that tracked the dataset, `ebe6e7c` (2026-04-16), still holds an earlier version of `vulnerable/`, `injectable/`, `phase3_sven_pyvul/` and `dev/`. This command copies it into your working tree without staging it, overwriting any local files with the same names:

```bash
git restore --source=ebe6e7c --worktree -- vaitp_dataset
```

## Usage

### Generate Mutation Files

```bash
# Generate 30 STDIO mutations (v2/v3/v4 for 10 categories)
python gold_standard/generate_mutations.py

# Generate 30 NETWORK mutations (v2/v3/v4 for 10 categories)
python gold_standard/generate_network_mutations.py
```

### Run Gold Standard Regression (20 tests, no LLM)

```bash
python test_phase3_regression.py                  # All 20
python test_phase3_regression.py flask_1.py       # Single test
python test_phase3_regression.py --stdio-only     # STDIO only
python test_phase3_regression.py --network-only   # Network only
```

### Run Mutation Tests (60 tests, no LLM)

```bash
python test_phase3_mutations.py                       # All 60
python test_phase3_mutations.py --category flask_rce   # Single category
python test_phase3_mutations.py flask_v2.py            # Single test
```

### Run Diagnostic Agent (Standard Mode — LLM fixes pre-written plans)

```bash
# Default model (deepthink-7b):
python test_phase3_diagnostic.py

# Specific model:
python test_phase3_diagnostic.py --model llama-3.1-8b

# Single category:
python test_phase3_diagnostic.py --category yaml

# Single test:
python test_phase3_diagnostic.py --test eval_v2.py

# Mock LLM (no GPU needed, for pipeline testing):
python test_phase3_diagnostic.py --mock

# Export report:
python test_phase3_diagnostic.py --export diagnostic_report.json
```

### Run Diagnostic Agent (Autonomous Mode — LLM reasons from scratch)

```bash
# Autonomous mode: LLM generates SEP/AEP from code analysis
python test_phase3_diagnostic.py --autonomous

# Autonomous with specific model:
python test_phase3_diagnostic.py --autonomous --model deepthink-7b

# Autonomous on single category:
python test_phase3_diagnostic.py --autonomous --category flask_rce
```

### Run Phase 1/2 Experiments

```bash
python main_orchestrator.py --config configs/IEEE_phase1.yaml
python main_orchestrator.py --config configs/IEEE_phase2.yaml
```

### Run Phase 3 with Ollama (Local)

```bash
python run_phase3.py --ollama --model deepseek-r1:14b                    # Full dataset
python run_phase3.py --ollama --model deepseek-r1:14b --filter flask     # Filter by name
python run_phase3.py --ollama --model deepseek-r1:14b --skip-proven      # Skip already-proven
python run_phase3.py --ollama --model deepseek-r1:14b --resume           # Skip proven + failed
python run_phase3.py --ollama --model deepseek-r1:14b --stream-llm      # Live token output
```

### Run Phase 3 with Vertex AI (Remote)

```bash
# Ensure you've authenticated first:
# gcloud auth application-default login

# Using the launcher script:
./run_vaitp_vertex.sh configs/config_deepseek.yaml
./run_vaitp_vertex.sh configs/config_gemini.yaml --filter eval --max-iterations 2
./run_vaitp_vertex.sh configs/config_qwen.yaml --max-iterations 5
./run_vaitp_vertex.sh configs/config_claude.yaml --filter eval

# Or directly (tokens are managed automatically by vertex_backend.py):
python run_phase3.py --vertex --vertex-config configs/config_deepseek.yaml --filter eval
```

### Run Phase 3 via main_orchestrator.py (Config-Driven)

```bash
# Vertex AI model via YAML config:
python main_orchestrator.py --config configs/config_deepseek.yaml

# Local Ollama model via YAML config:
python main_orchestrator.py --config configs/test_phase3_deepseek_r1_14b.yaml

# Full pipeline testing ALL Phase 2 variants (not just promoted best):
python main_orchestrator.py --config configs/my_config.yaml --phase3-test-all

# Skip LLM vulnerability identification — use a fixed type for all files:
python main_orchestrator.py --config configs/my_config.yaml --intended-vulnerability "SQL Injection"
```

### List Available Local Models

```bash
python test_phase3_diagnostic.py --list-models
# Or check Ollama directly:
ollama list
```

### List Available parameters:
```bash
python main_orchestrator.py --help
```

## Design Principles

1. **Side-Effects Over Output** — Never rely on stdout for exploitation proof. Always use file creation (`touch /tmp/pwned_*`) or time delays.
2. **Base64 for CLI** — All STDIO payloads are Base64-encoded before piping to containers to avoid shell escaping issues.
3. **Aggressive Cleanup** — `pkill -9 -f python` before starting network services to free ports.
4. **Ground Truth Fidelity** — All logic paths handle edge cases from `run_all_poc_tests.py` (git timeouts, pickle protocol versions, Flask port conflicts).
5. **Deterministic + Autonomous** — Regression tests are deterministic (known SEP/AEP). Autonomous mode lets the LLM generate everything from scratch.
6. **Learning from Failure** — The feedback loop converts Truth Table violations into actionable suggestions that the Planner uses to self-correct.
7. **Model-Agnostic** — The framework supports local (Ollama, llama-cpp) and remote (Vertex AI) backends interchangeably via configuration. Chat templates are handled by the backend, not hardcoded.
8. **Fail Fast on Fatal Errors** — Non-retryable API errors (400, 401, 403, 404, 429 quota exhaustion) trigger immediate `sys.exit(1)` via `VertexFatalError` instead of burning through iterations.
9. **Thinking Token Hygiene** — `<think>...</think>` blocks from reasoning models (DeepSeek R1, Qwen3) are stripped at both the backend level (`vertex_backend.py`) and the parser level (`_extract_json_block`) to prevent contamination of JSON extraction.
10. **Explainability by Design** — Every LLM call, Docker command, and verification decision can be traced and audited via the execution trace report.
11. **Self-Improving Discovery** — Each confirmed zero-day feeds back into the RAG database, improving future scans. Built-in tests are added for each new vulnerability class discovered.

## Phase 0: Zero-Day Discovery Mode

Phase 0 is a **proactive vulnerability discovery pipeline** that takes a git repository as input and autonomously searches for zero-day vulnerabilities. Unlike Phases 1-3 (which inject known vulnerability patterns), Phase 0 discovers *unknown* vulnerabilities in real-world code.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  run_discovery.py (CLI entry point)                         │
│  Input: git URL or local path                               │
│  Output: results/discovery_<repo>.json + disclosure reports │
├─────────────────────────────────────────────────────────────┤
│  Stage 1: Attack Surface Mapping (AST-based, no LLM)        │
│  → Identifies security-relevant functions by category       │
│  → Confidence scoring based on keyword density              │
├─────────────────────────────────────────────────────────────┤
│  Stage 1b: Taint Analysis (--taint flag)                    │
│  → Source-to-sink data flow tracking                        │
│  → Tracks: function params, input(), request.*, os.environ  │
│  → Sinks: eval, os.system, cursor.execute, open, pickle...  │
│  → Recognizes sanitizers that break taint flow              │
├─────────────────────────────────────────────────────────────┤
│  Stage 2a: Built-in Vulnerability Checks (no LLM needed)    │
│  → Deterministic tests for known vulnerability patterns     │
│  → Auth bypass: missing claim acceptance                    │
│  → Algorithmic DoS: timing-based complexity detection       │
├─────────────────────────────────────────────────────────────┤
│  Stage 2b: LLM Hypothesis Generation (local model)          │
│  → "What could go wrong?" for each attack surface           │
│  → Generates self-contained test scripts                    │
├─────────────────────────────────────────────────────────────┤
│  Stage 3: Dynamic Testing (subprocess with timeout)         │
│  → Executes test scripts, catches VULNERABLE/TIMEOUT        │
│  → No Docker needed for most tests                          │
├─────────────────────────────────────────────────────────────┤
│  Stage 4: LLM Review (--llm-review flag)                    │
│  → Severity assessment, CWE classification                  │
│  → CVE likelihood estimation                                │
├─────────────────────────────────────────────────────────────┤
│  Stage 5: Disclosure Generation (--generate-disclosure)     │
│  → Auto-generates markdown reports for confirmed findings   │
│  → Includes PoC, MITRE description, suggested issue title   │
└─────────────────────────────────────────────────────────────┘
```

### Usage

```bash
# Basic scan (built-in tests + LLM hypotheses):
venv/bin/python3 run_discovery.py https://github.com/user/repo

# Quick surface mapping (no testing, no LLM):
venv/bin/python3 run_discovery.py /path/to/repo --surface-only

# Surface mapping with taint analysis:
venv/bin/python3 run_discovery.py /path/to/repo --surface-only --taint

# LLM-only mode (skip built-in static tests, use only LLM hypotheses):
venv/bin/python3 run_discovery.py /path/to/repo --llm-only --model deepseek-r1:14b

# Full pipeline with LLM review and disclosure generation:
venv/bin/python3 run_discovery.py /path/to/repo --llm-review --generate-disclosure --taint

# Custom settings:
venv/bin/python3 run_discovery.py https://github.com/user/repo \
    --model deepseek-r1:14b \
    --max-surfaces 30 \
    --max-hypotheses 20 \
    --timeout 60
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `--surface-only` | Only map attack surfaces (fast, no testing) |
| `--taint` | Run source-to-sink taint analysis |
| `--llm-only` | Skip built-in tests, use only LLM-generated hypotheses |
| `--llm-review` | Use LLM to assess severity and CVE likelihood after testing |
| `--generate-disclosure` | Auto-generate disclosure reports for confirmed findings |
| `--model MODEL` | Ollama model for LLM stages (default: deepseek-r1:14b) |
| `--max-surfaces N` | Max attack surfaces to analyze (default: 20) |
| `--max-hypotheses N` | Max LLM hypotheses to generate (default: 10) |
| `--timeout N` | Timeout per dynamic test in seconds (default: 30) |
| `--output PATH` | Custom output JSON path |

### Taint Tracking

The taint tracker (`orchestration/taint_tracker.py`) performs intra-procedural data flow analysis:

**Sources** (where untrusted data enters):
- Function parameters (any non-self/cls argument)
- `input()`, `readline()`, `recv()`
- `request.args`, `request.form`, `request.json`, `request.headers`
- `os.environ`, `sys.argv`

**Sinks** (where untrusted data is dangerous):
- `eval()`, `exec()` → Code Injection (CWE-94)
- `os.system()`, `subprocess.Popen()` → Command Injection (CWE-78)
- `cursor.execute()` → SQL Injection (CWE-89)
- `render_template_string()` → SSTI (CWE-1336)
- `open()`, `extractall()` → Path Traversal (CWE-22)
- `pickle.loads()`, `yaml.load()` → Deserialization (CWE-502)
- `requests.get()`, `urlopen()` → SSRF (CWE-918)
- `os.symlink()` → Symlink Following (CWE-59)

**Sanitizers** (break the taint chain):
- `shlex.quote()`, `html.escape()`, `int()`, `float()`
- `os.path.basename()`, `re.escape()`, `bleach.clean()`

### Built-in Vulnerability Checks

These run without the LLM and detect vulnerabilities deterministically:

| Category | Detection Method |
|----------|-----------------|
| `auth_bypass` | Creates a JWT without `aud` claim, attempts decode with `audience=` specified |
| `algorithmic_dos` | Measures parsing time at 4 input sizes, detects super-linear growth |

More built-in checks can be added to `BUILTIN_TESTS` in `orchestration/discovery_agent.py`.

### Confirmed Zero-Days Found

| Library | Vulnerability | CWE | Status |
|---------|--------------|-----|--------|
| python-jose 3.5.0 | JWT audience validation bypass | CWE-287 | Disclosed (GitHub #407 + MITRE) |
| tomlkit 0.15.0 | Quadratic complexity DoS via dotted keys | CWE-400 | Confirmed, disclosure pending |

### Self-Improvement Loop

Each confirmed finding feeds back into the framework:
1. **RAG database** — New CVE added to netpack.pt MySQL → `rag_updater.py` pulls it
2. **SECURITY_PATTERNS** — New detection patterns added to `discovery_agent.py`
3. **BUILTIN_TESTS** — New deterministic checks for the vulnerability class
4. **HYPOTHESIS_TEMPLATES** — New question templates for the LLM
5. **Gold standard registry** — New proven exploits for Phase 3 learning

### File Reference (Phase 0)

| File | Purpose |
|------|---------|
| `run_discovery.py` | CLI entry point for zero-day discovery |
| `orchestration/discovery_agent.py` | Core discovery pipeline: surface mapping, hypothesis generation, testing |
| `orchestration/taint_tracker.py` | Source-to-sink taint analysis |
| `scripts/repo_scanner.py` | Repository download, attack surface analysis, scan input preparation |
| `rag_updater.py` | RAG index update from MySQL database |

### RAG Index Update

The FAISS index used by the RAG component can be updated from the MySQL database at netpack.pt:

```bash
# Automatic update on startup (checks if DB has new records):
venv/bin/python3 main_orchestrator.py --config configs/my_config.yaml

# Force update:
venv/bin/python3 main_orchestrator.py --config configs/my_config.yaml --force-rag-update

# Disable update:
venv/bin/python3 main_orchestrator.py --config configs/my_config.yaml --no-rag-update

# Standalone update:
venv/bin/python3 rag_updater.py --force
```

## Execution Tracing (Explainability)

The framework includes an execution tracing system that produces a self-contained HTML report documenting every decision and interaction throughout a run. This is designed for audit and explainability — allowing researchers and reviewers to inspect the full chain of reasoning from initial code analysis through exploitation to final verdict.

### Enabling Tracing

Add to your YAML config:

```yaml
trace_diagram: true
trace_detail_level: full    # minimal | standard | detailed | full
```

Or via CLI:

```bash
python main_orchestrator.py --config configs/my_config.yaml --trace-diagram --trace-detail-level full
```

### What the Trace Captures

The HTML report includes, in chronological order:

- **Invocation command** — the exact CLI command used to launch the framework
- **Full configuration** — all YAML and CLI parameters merged
- **Phase transitions** — Phase 1 → 2 → Promote → 3 with context (model, strategies, input directory)
- **Every LLM prompt and response** — complete, untruncated text for every call across all agents (vulnerability identification, plan generation, code generation, static analysis evaluation, semantic evaluation, exploitation planning, diagnostic analysis, fuzzing). A transparent wrapper intercepts all LLM calls automatically.
- **RAG context** — retrieved vulnerability examples with full text
- **Static analysis outputs** — Bandit, Semgrep, and DeVAIC findings
- **Promotion decisions** — which code variant was selected, the scoring formula, all candidates compared
- **Docker commands** — the exact `curl` commands, payloads, and container outputs for each exploit and functional check
- **Verification verdicts** — PASS/FAIL with failure reasons, exploit outputs, and functional test results
- **Self-correction iterations** — each iteration traced individually showing how the plan evolves

### Output

A single `.html` file is produced in `results/`, named `{experiment_name}_trace_{timestamp}.html`. Open it in any browser. LLM prompts are shown in orange expandable blocks, responses in green, RAG context in purple, and Docker commands in terminal-style boxes.

### Detail Levels

| Level | Content |
|---|---|
| `minimal` | Phase transitions and final outcomes only |
| `standard` | + LLM call summaries, RAG hits, analysis verdicts |
| `detailed` | + Prompt/response previews, timing, scores |
| `full` | + Complete untruncated prompts and responses (recommended for audits) |

## Configuration

### LLM Engine Settings (`config.py`)

```python
LLM_N_GPU_LAYERS = -1     # Use all GPU layers (MPS on macOS)
LLM_N_CTX = 8192          # Default context size
LLM_N_THREADS = 4         # CPU threads
LLM_USE_MMAP = True       # Memory-mapped model loading
LLM_USE_CUDA = False      # macOS (set True for NVIDIA)
```

### Default Docker Settings

- Base image: `python:3.9-slim`
- Working directory: `/app`
- Network: `vaitp_net` (bridge)
- Sidecar support: MongoDB (`mongo:4.4`), extensible to MySQL, Redis, etc.

### YAML Experiment Configs (`configs/`)

Phase 1/2 experiments are configured via YAML files specifying models, strategies, datasets, and output paths.

Additional configuration options:

```yaml
# Skip LLM vulnerability identification — use this type for all input files
intended_vulnerability: "SQL Injection"
# Or with full details:
intended_vulnerability:
  type: "SQL Injection"
  cwe: "CWE-89"
  expected_pattern: "cursor.execute(f'SELECT ...')"

# Test ALL Phase 2 generated codes in Phase 3 (not just the promoted best)
phase3_test_all: true

# Enable execution tracing for explainability (produces HTML report)
trace_diagram: true
trace_detail_level: full    # minimal | standard | detailed | full
```

Vertex AI configs include additional fields:

```yaml
# Required for Vertex AI
vertex: true
vertex_config: "configs/config_deepseek.yaml"  # self-reference for load_vertex_config()
model: deepseek-ai/deepseek-r1-0528-maas       # Vertex AI model ID
api_base: https://us-central1-aiplatform.googleapis.com/v1/projects/PROJECT_ID/locations/REGION/endpoints/openapi
api_key_env: VERTEX_ACCESS_TOKEN                # env var name (token refreshed by vertex_backend.py)
```

Available Vertex AI configs:
- `configs/config_deepseek.yaml` — DeepSeek R1-0528 (us-central1)
- `configs/config_gemini.yaml` — Gemini 2.5 Pro (us-central1)
- `configs/config_qwen.yaml` — Qwen3-235B (global)
- `configs/config_claude.yaml` — Claude Sonnet 4.6 (global, Anthropic SDK)
- `configs/config_claude_opus.yaml` — Claude Opus 4.6 (global, optional)

## Dependencies

```
# Core
python >= 3.8
docker (running daemon)
llama-cpp-python or ollama (for local LLM inference)

# Phase 1/2
torch, transformers, faiss-cpu, sacrebleu
bandit, semgrep, devaic (static analysis)
tiktoken (token counting)

# Phase 3
docker (Python SDK)
PyYAML, jinja2, Mako, lxml, gitpython, flask, pymongo, pyjwt (test dependencies — installed in containers)

# Vertex AI (remote LLM inference)
openai >= 1.30.0 (OpenAI-compatible endpoint for Gemini, DeepSeek, Qwen)
anthropic[vertex] >= 0.40.0 (Anthropic SDK for Claude models on Vertex)
gcloud CLI (for access token refresh)

# Optional
tree-sitter (CodeBLEU), rouge-score, editdistance
oLLM (70B+ model support)
psutil (resource monitoring)
```

## Research Vision

VAITP Phase 3 enables research in autonomous vulnerability verification:

- **Autonomous Reasoning**: LLMs analyze code, generate exploitation plans, test them in Docker, and learn from failures — without human-written test plans.
- **Self-Correcting Agents**: The feedback loop converts test failures into actionable suggestions, enabling iterative improvement.
- **Mutation Testing at Scale**: 60 mutation variants across 20 vulnerability categories calibrate the system and measure the agent's generalization ability.
- **Evolving Knowledge**: Successful plans are accumulated as "learned examples" that can inform future exploitation attempts, building an expanding knowledge base.
- **Multi-Model Comparison**: Vertex AI integration enables controlled comparison across open vs. closed and reasoning vs. non-reasoning models (DeepSeek R1, Qwen3, Gemini 2.5 Pro, Claude Sonnet 4.6) on the same dataset.
- **Proof of Concept Generation**: The end goal is automated generation of working PoCs and patches for known vulnerabilities, proving exploitability in controlled environments.

Start by checking out "python3 main_orchestrator.py --help".
Hope you have fun and that this code helps you brainstorm :-)
Plase note that this is still a work in progress and I'm still writing the code to then write my thesis on this (please don't share or use besides research while I'm still finishing).

💙

Thank you :-)

Bjs,
/F.