import os
from typing import Dict, Any

# Import oLLM configuration utilities
try:
    from config_utils import OLLMConfig, merge_ollm_configs
except ImportError:
    # Fallback if config_utils is not available
    OLLMConfig = None
    merge_ollm_configs = None

# --- Path Configuration ---
# Updated for standalone VAITP framework directory
USER_HOME = os.path.expanduser('~')
VAITP_PATH = os.path.join(USER_HOME, "vaitp-framework")

# --- Main GGUF Model Configuration ---
REASONING_MODELS = {
    #  "deepthink-7b": {
    #     "path": os.path.join(USER_HOME, "models", "Deepthink-Reasoning-7B-Q8_0.gguf"),
    #     "format": "chatml",
    #     "context_window": 32768  # DeepThink supports up to 32K context
    # },
    
    "qwen2.5-coder-3b-abliterated-basic:latest": {
        "path": os.path.join(USER_HOME, "Downloads", "qwen2.5-coder-3b-abliterated-basic.gguf"),
        "format": "chatml",
        "context_window": 8192
    },

    "llama-3.1-8b": {
        "path": os.path.join(USER_HOME, "models", "Meta-Llama-3.1-8B-Instruct-Q8_0.gguf"),
        "format": "llama3",
        "context_window": 8192 #131072  # Llama 3.1 supports up to 128K context
    },
    # "llama-3.2-1b": {
    #     "path": os.path.join(USER_HOME, "models", "Llama-3.2-1B-Base-Q4_K_M.gguf"),
    #     "format": "llama3",
    #     "context_window": 131072  # Llama 3.2 supports up to 128K context
    # },
    # "qwen-3-1.7b": {
    #     "path": os.path.join(USER_HOME, "models", "Qwen-3-1.7B-Base.Q4_K_M.gguf"),
    #     "format": "chatml",
    #     "context_window": 32768  # Qwen 2.5/3 typically supports 32K context
    # },
    # "nemotron-nano-9b": { # NEMOTRON WILL ONLY BY SUPPORTED BY LLAMACPP IN A FUTURE VERSION
    #     "path": os.path.join(USER_HOME, "models", "Nemotron-Nano-9B-v2-Q8_0.gguf"),
    #     "format": "chatml", # Nemotron uses a ChatML-like format albeit it's a NVIDIA model family per se.. :-)
    #     "context_window": 4096   # Nemotron Nano typically has 4K context
    # },
    # "agi-0-8b": { # Not workin' bro.. at least on mps..
    #     "path": os.path.join(USER_HOME, "models", "AGI-0_Art-0-8B-Q8_0.gguf"),
    #     "format": "chatml", 
    #     "context_window": 2048
    # },

    #  "llama-3.1-8b-uncensored": { # bad model, only managed to generate 3 prompts in phase 1.. leaving so we don't make the same mistake twice
    #     "path": os.path.join(USER_HOME, "models", "Llama-3-8B-Lexi-Uncensored.Q6_K.gguf"),
    #     "format": "llama3",
    #     "context_window": 131072  # Llama 3.1 supports up to 128K context
    # },

    "deepseek-r1:14b": {
        "path": os.path.join(USER_HOME, ".ollama/models/blobs/", "sha256-6e9f90f02bb3b39b59e81916e8cfce9deb45aeaeb9a54a5be4414486b907dc1e"),
        "format": "chatml",
        "context_window": 8192  # Capped for macOS 18GB RAM — 32K causes llama_decode -3
    },

    "gemma": {
        "path": os.path.join(USER_HOME, "Downloads", "gemma-3-12b-it-jailbreak-EN.i1-Q6_K.gguf"),
        "format": "chatml",
        "context_window": 8192  # Conservative for macOS 18GB RAM
    },

    # oLLM Large Models for Testing
    # "meta-llama-3.1-70b-instruct": {
    #     "path": os.path.join(USER_HOME, "models", "Meta_Llama_3_1_70B_Instruct"),
    #     "format": "llama3",
    #     "context_window": 32768,
    #     "parameters": 70600000000,
    #     "backend": "ollm",
    #     "description": "Meta Llama 3.1 70B Instruct - oLLM testing"
    # },

    # "qwen3-next-80b-thinking": {
    #     "path": os.path.join(USER_HOME, "models", "Qwen3_Next_80B_A3B_Thinking"),
    #     "format": "chatml",
    #     "context_window": 32768,
    #     "parameters": 80000000000,
    #     "backend": "ollm", 
    #     "description": "Qwen3-Next 80B A3B Thinking - oLLM testing"
    # },
    
    
}

CODER_MODELS = {

    # Installed Ollama coder tag (fast, code-focused) — used for jury full-pipeline tests.
    "qwen2.5-coder:1.5b": {
        "path": os.path.join(USER_HOME, ".ollama", "models"),  # unused for the Ollama backend
        "format": "chatml",
        "context_window": 8192
    },

    "qwen2.5-coder-3b-abliterated-basic:latest": {
        "path": os.path.join(USER_HOME, "Downloads", "qwen2.5-coder-3b-abliterated-basic.gguf"),
        "format": "chatml",
        "context_window": 8192
    },

    "deepseek-r1:14b": {
        "path": os.path.join(USER_HOME, ".ollama/models/blobs/", "sha256-6e9f90f02bb3b39b59e81916e8cfce9deb45aeaeb9a54a5be4414486b907dc1e"),
        "format": "chatml",
        "context_window": 8192  # Capped for macOS 18GB RAM
    },

    "gemma": {
        "path": os.path.join(USER_HOME, "Downloads", "gemma-3-12b-it-jailbreak-EN.i1-Q6_K.gguf"),
        "format": "chatml",
        "context_window": 8192  # Conservative for macOS 18GB RAM
    },

    # "deepthink-7b": {
    #     "path": os.path.join(USER_HOME, "models", "Deepthink-Reasoning-7B-Q8_0.gguf"),
    #     "format": "chatml",
    #     "context_window": 32768
    # },
    "llama-3.1-8b": {
        "path": os.path.join(USER_HOME, "models", "Meta-Llama-3.1-8B-Instruct-Q8_0.gguf"),
        "format": "llama3",
        "context_window": 8192 # 131072  # Llama 3.1 supports up to 128K context
    },

    # "llama-3.1-8b-uncensored": {
    #     "path": os.path.join(USER_HOME, "models", "Llama-3-8B-Lexi-Uncensored.Q6_K.gguf"),
    #     "format": "llama3",
    #     "context_window": 131072  # Llama 3.1 supports up to 128K context
    # },

    # "Llama-3.2-1B-Base": { 
    #     "path": os.path.join(USER_HOME, "models", "Llama-3.2-1B-Base-Q4_K_M.gguf"),
    #     "format": "llama3",
    #     "context_window": 131072
    # },
    # "Llama-3.2-1B-Finetuned": { 
    #     "path": os.path.join(USER_HOME, "models", "Llama-3.2-1B-Finetuned.Q4_K_M.gguf"),
    #     "format": "llama3",
    #     "context_window": 131072
    # },

    # "Qwen3-1.7B-Base": { 
    #     "path": os.path.join(USER_HOME, "models", "Qwen-3-1.7B-Base.Q4_K_M.gguf"),
    #     "format": "chatml",
    #     "context_window": 32768
    # },
    # "Qwen-3-1.7B-Finetuned": { 
    #     "path": os.path.join(USER_HOME, "models", "Qwen-3-1.7B-Finetuned.Q4_K_M.gguf"),
    #     "format": "chatml",
    #     "context_window": 32768
    # },

    # "Codepy-3B-Base": { 
    #     "path": os.path.join(USER_HOME, "models", "Codepy-3B-Base.Q4_K_M.gguf"),
    #     "format": "llama3",
    #     "context_window": 8192  # CodePy models typically have 8K context
    # },
    # "Codepy-3B-Finetuned": { 
    #     "path": os.path.join(USER_HOME, "models", "Codepy-3B-Finetuned.Q4_K_M.gguf"),
    #     "format": "llama3",
    #     "context_window": 8192
    # },

    # "Qwen-2.5-7B-Base": { 
    #     "path": os.path.join(USER_HOME, "models", "Qwen-2.5-7B-Base-Q4_K_M.gguf"),
    #     "format": "chatml",
    #     "context_window": 32768
    # },
    # "Qwen2.5-7B-Finetuned": { 
    #     "path": os.path.join(USER_HOME, "models", "NextCoder-7B-Finetuned.Q4_K_M.gguf"),
    #     "format": "chatml",
    #     "context_window": 32768
    # },

    # "Qwen-3-8B-Base": { 
    #     "path": os.path.join(USER_HOME, "models", "Qwen-3-8B-Base.Q4_K_M.gguf"),
    #     "format": "chatml",
    #     "context_window": 32768
    # },
    # "Qwen3-8B-Finetuned": { 
    #     "path": os.path.join(USER_HOME, "models", "Qwen-3-8B-Finetuned.Q4_K_M.gguf"),
    #     "format": "chatml",
    #     "context_window": 32768
    # },

    # "Llama-3.1-8B-Base": { 
    #     "path": os.path.join(USER_HOME, "models", "Llama-3.1-8B-Base-Q4_K_M.gguf"),
    #     "format": "llama3",
    #     "context_window": 131072
    # },
    # "Llama-3.1-8B-Finetuned": { 
    #     "path": os.path.join(USER_HOME, "models", "Llama-3.1-8B-Finetuned.Q4_K_M.gguf"),
    #     "format": "llama3",
    #     "context_window": 131072
    # },


}

# --- Llama.cpp Engine Settings ---
# Conservative settings for macOS with limited memory
LLM_N_GPU_LAYERS = -1     # Use all GPU layers for MPS
LLM_N_CTX = 8192          # Default context size (overridden by model-specific settings)
LLM_N_THREADS = 4         # A safe number of threads for the n1-standard-8 CPU
LLM_USE_MMAP = True       # Use memory mapping for faster loads
LLM_USE_MLOCK = False     # Don't lock model in memory to allow swapping
#LLM_USE_CUDA = True      # Vertex IMPORTANT: Enable CUDA for the NVIDIA GPU
LLM_USE_CUDA = False      # Mac

# --- Project Paths ---
PROMPTS_DIR = os.path.join(VAITP_PATH, "generated_prompts") 
DB_PATH = os.path.join(VAITP_PATH, "execution_log_orchestrated.db")

def get_model_specific_prompts_dir(model_name: str, experiment_name: str = None) -> str:
    """
    Get a model-specific prompts directory to avoid conflicts between different models.
    
    Args:
        model_name: The model name (e.g., 'deepthink-7b', 'llama-3.1-8b')
        experiment_name: Optional experiment name for further organization
        
    Returns:
        Path to model-specific prompts directory
    """
    if experiment_name:
        return os.path.join(VAITP_PATH, f"generated_prompts_{experiment_name}_{model_name}")
    else:
        return os.path.join(VAITP_PATH, f"generated_prompts_{model_name}")

def ensure_prompts_dir_exists(prompts_dir: str) -> str:
    """
    Ensure the prompts directory exists and return its path.
    
    Args:
        prompts_dir: Path to the prompts directory
        
    Returns:
        The same path after ensuring it exists
    """
    os.makedirs(prompts_dir, exist_ok=True)
    return prompts_dir

# --- Static Analysis Tool Paths ---
DEVAIC_DIR = os.path.join(USER_HOME, "DeVAIC") 
DEVAIC_PATH = os.path.join(DEVAIC_DIR, "devaic.sh")
BANDIT_COMMAND = "bandit"
SEMGREP_COMMAND = "semgrep"

# --- RAG/FAISS Configuration ---
# Ensure these files are uploaded to the VAITP_AI_AGENT directory on the Workbench
FAISS_INDEX_PATH = os.path.join(VAITP_PATH, "index.faiss")
CLEANED_CSV_PATH = os.path.join(VAITP_PATH, "cleaned_python_vulnerabilities.csv")
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
RAG_TOP_K = 1

# --- Docker Configuration ---
# These are needed for the dynamic analysis phase.
DOCKER_IMAGE = "python:latest"
DOCKER_COMMAND = "bash"
DOCKER_WORKDIR = "/vaitp_test_code"
DOCKER_GENERATED_CODE_FILENAME = "response_code.py"
DOCKER_SERVER_LOG_FILENAME = "server.log"

target_directory = "~/DeVAIC/input"

# --- Timeout Configuration ---
# Centralised timeouts for LLM calls.  Local models (Ollama / llama-cpp) run on
# constrained hardware and may need a long time; remote APIs (Vertex AI) are
# faster but still need a reasonable ceiling.
#
# These values are imported by the orchestrator, phase runners, and agents so
# that every call site stays consistent.
LOCAL_LLM_TIMEOUT = 900        # 15 min — local model generation (Ollama / llama-cpp HTTP)
LOCAL_LLM_SIGNAL_TIMEOUT = 900 # 15 min — signal.alarm guard for local LLM calls
REMOTE_API_TIMEOUT = 300       # 5 min  — remote API calls (Vertex AI, OpenAI-compat)
HEALTH_CHECK_TIMEOUT = 30      # 30 sec — Ollama /api/tags health check (per attempt)

# Max attempts to get the generated code correctly
max_sanitize_attempts = 5 

# Max attempts to inject a vulnerability in agiven input file
MAX_INJECTION_ATTEMPTS = 5

# Max attempts to generate a prompt
MAX_PROMPT_ATTEMPTS = 3 

# Dynamic Test Flag 
DEFAULT_DYNAMIC_TEST = False

# Output paths
GENERATED_CODE_DIR = os.path.join(VAITP_PATH, "generated_vulnerable_code")
AEP_DIR = os.path.join(VAITP_PATH, "generated_aeps")
EXPLOITED_CODE_DIR = os.path.join(GENERATED_CODE_DIR, "exploited")

# --- Code Similarity Metrics Configuration ---
# Configuration for comprehensive code similarity evaluation

# Metric enablement flags - allows selective metric calculation
METRICS_CONFIG = {
    "enable_code_bleu": True,       # Enable CodeBLEU calculation (AST-based)
    "enable_bleu_4": True,          # Enable BLEU-4 calculation (standard baseline)
    "enable_rouge_l": True,         # Enable ROUGE-L calculation (longest common subsequence)
    "enable_edit_distance": True,   # Enable normalized edit distance calculation
}

# Performance and resource limits
METRICS_PERFORMANCE_CONFIG = {
    "max_code_size_bytes": 1_000_000,      # Maximum code size for evaluation (1MB)
    "max_tokens_per_file": 10_000,         # Maximum tokens per file for tokenization
    "ast_parsing_timeout_seconds": 30,      # Timeout for AST parsing operations
    "memory_limit_mb": 100,                 # Memory limit per evaluation (MB)
    "enable_parallel_calculation": False,   # Enable parallel metric calculation
}

# Metric weight configuration for composite scoring
METRICS_WEIGHTS = {
    "code_bleu_weight": 0.4,        # Weight for CodeBLEU in composite score
    "bleu_4_weight": 0.2,           # Weight for BLEU-4 in composite score
    "rouge_l_weight": 0.2,          # Weight for ROUGE-L in composite score
    "edit_distance_weight": 0.2,    # Weight for edit distance in composite score
}

# Fallback configuration when dependencies are missing
METRICS_FALLBACK_CONFIG = {
    "fallback_to_bleu_only": True,          # Fall back to BLEU-4 only if other metrics fail
    "log_missing_dependencies": True,        # Log warnings for missing dependencies
    "fail_gracefully": True,                 # Continue evaluation even if some metrics fail
    "default_failed_metric_value": -1.0,    # Value to use for failed metric calculations
}

# Legacy BLEU Score Configuration (maintained for backward compatibility)
BLEU_TOKENIZER = "13a"  # Standard tokenizer for BLEU calculation
BLEU_LOWERCASE = True   # Convert to lowercase for comparison
BLEU_SMOOTH_METHOD = "exp"  # Exponential smoothing for short sequences
BLEU_SMOOTH_VALUE = None    # Use default smoothing value
BLEU_USE_EFFECTIVE_ORDER = True  # Use effective n-gram order (default)

# Code preprocessing options for BLEU calculation
CODE_NORMALIZE_WHITESPACE = True    # Normalize whitespace in code
CODE_REMOVE_COMMENTS = True         # Remove comments before comparison
CODE_REMOVE_DOCSTRINGS = True       # Remove docstrings before comparison
CODE_NORMALIZE_IDENTIFIERS = False  # Keep original identifier names

# --- Database Schema Configuration ---
# Configuration for enhanced database schema with attempt tracking

# Attempt tracking settings
ENABLE_ATTEMPT_TRACKING = True      # Enable detailed attempt logging
MAX_ATTEMPTS_TO_LOG = 5             # Maximum attempts to log per injection
LOG_ATTEMPT_DETAILS = True          # Log detailed attempt information
LOG_BLEU_SCORES = True              # Log BLEU scores for each attempt

# Database table names (for potential future customization)
MAIN_RUNS_TABLE = "comparative_analysis_runs"
ATTEMPTS_TABLE = "injection_attempts"

# Database connection settings
DB_TIMEOUT = 30.0                   # Database connection timeout in seconds
DB_RETRY_ATTEMPTS = 3               # Number of retry attempts for DB operations
DB_RETRY_DELAY = 1.0                # Delay between retry attempts in seconds
DB_ENABLE_FOREIGN_KEYS = True       # Enable foreign key constraints
DB_ENABLE_WAL_MODE = False          # Enable Write-Ahead Logging mode for better concurrency
DB_CACHE_SIZE = -2000               # Cache size in KB (negative = KB, positive = pages)
DB_SYNCHRONOUS = "NORMAL"           # Synchronous mode: OFF, NORMAL, FULL

# Similarity evaluation parameters
SIMILARITY_THRESHOLD_HIGH = 80.0    # High similarity threshold for BLEU scores
SIMILARITY_THRESHOLD_MEDIUM = 60.0  # Medium similarity threshold for BLEU scores
SIMILARITY_THRESHOLD_LOW = 40.0     # Low similarity threshold for BLEU scores

# Logging and metadata settings
LOG_TIMESTAMPS = True               # Include timestamps in attempt logs
LOG_SEMANTIC_JUSTIFICATIONS = True  # Log LLM semantic evaluation justifications
LOG_STATIC_ANALYSIS_REPORTS = True  # Log static analysis reports
COMPRESS_LARGE_LOGS = False         # Compress large log entries (future feature)

# --- Context Window Management ---
def get_model_context_window(model_path: str, default_context: int = 8192) -> int:
    """
    Get the configured context window size for a model based on its path.
    
    Args:
        model_path: Path to the model file
        default_context: Default context window if model not found in config
        
    Returns:
        Context window size in tokens
    """
    # Check reasoning models first
    for model_key, model_info in REASONING_MODELS.items():
        if model_info['path'] == model_path:
            return model_info.get('context_window', default_context)
    
    # Check coder models
    for model_key, model_info in CODER_MODELS.items():
        if model_info['path'] == model_path:
            return model_info.get('context_window', default_context)
    
    # If not found, return default
    return default_context

def get_model_info_by_key(model_key: str, model_type: str = 'reasoning') -> dict:
    """
    Get model information by key from the appropriate model dictionary.
    
    Args:
        model_key: The model key (e.g., 'llama-3.2-1b')
        model_type: Either 'reasoning' or 'coder'
        
    Returns:
        Model information dictionary or empty dict if not found
    """
    if model_type == 'reasoning':
        return REASONING_MODELS.get(model_key, {})
    elif model_type == 'coder':
        return CODER_MODELS.get(model_key, {})
    else:
        return {}

def get_model_path_from_name(model_name: str) -> str:
    """
    Get model path from model name by searching through all model configurations.
    
    Args:
        model_name: The model name (could be filename or model key)
        
    Returns:
        Model path or None if not found
    """
    # First try to match by model key
    for model_key, model_info in REASONING_MODELS.items():
        if model_key == model_name:
            return model_info['path']
    
    for model_key, model_info in CODER_MODELS.items():
        if model_key == model_name:
            return model_info['path']
    
    # Then try to match by filename in path
    for model_key, model_info in REASONING_MODELS.items():
        if model_name in model_info['path']:
            return model_info['path']
    
    for model_key, model_info in CODER_MODELS.items():
        if model_name in model_info['path']:
            return model_info['path']
    
    return None

# --- oLLM Configuration ---
# Configuration for oLLM integration to enable running large models on consumer hardware

# Global oLLM settings
OLLM_CONFIG = {
    "enable_ollm": True,                    # Global oLLM enable/disable
    "ollm_auto_detect": True,               # Auto-detect when to use oLLM
    "ollm_device": "auto",                  # Device selection: "auto", "cuda", "mps", "cpu"
    "ollm_logging": True,                   # Enable oLLM logging
    "ollm_memory_threshold_gb": 12.0,       # Use oLLM only for very large models (>12GB)
    "ollm_ssd_min_space_gb": 10.0,          # Minimum SSD space required
    "ollm_fallback_enabled": True,          # Enable fallback to llama-cpp
}

# Model-specific oLLM overrides
OLLM_MODEL_OVERRIDES = {
    "llama-3.1-8b": {
        "force_ollm": False,                # Never use oLLM for this model
        "device": "mps"                     # Use MPS on Mac
    },
    "deepthink-7b": {
        "force_ollm": False,               # Never use Ollama for 7B model
        "device": "mps"
    },
    "nemotron-nano-9b": {
        "force_ollm": True,                 # Force oLLM for large models
        "device": "auto",
        "ollm_memory_threshold_gb": 1.0     # Lower threshold for this model
    },
    
    # Large oLLM Models
    "meta-llama-3.1-70b-instruct": {
        "force_ollm": True,
        "device": "auto",
        "ollm_memory_threshold_gb": 1.0,
        "prefetch_layers": 2,
        "batch_size": 1,
        "precision": "fp16"
    },
    "qwen3-next-80b-thinking": {
        "force_ollm": True,
        "device": "auto", 
        "ollm_memory_threshold_gb": 1.0,
        "prefetch_layers": 2,
        "batch_size": 1,
        "precision": "fp16"
    }
}

def get_ollm_config(model_name: str) -> Dict[str, Any]:
    """
    Get oLLM configuration for a specific model.
    
    Args:
        model_name: The model name (e.g., 'deepthink-7b', 'llama-3.1-8b')
        
    Returns:
        Dict[str, Any]: oLLM configuration with model-specific overrides applied
    """
    base_config = OLLM_CONFIG.copy()

    # Apply model-specific overrides
    if model_name in OLLM_MODEL_OVERRIDES:
        base_config.update(OLLM_MODEL_OVERRIDES[model_name])

    return base_config


def get_ollm_config_structured(model_name: str) -> 'OLLMConfig':
    """
    Get structured oLLM configuration for a specific model.
    
    Args:
        model_name: The model name (e.g., 'deepthink-7b', 'llama-3.1-8b')
        
    Returns:
        OLLMConfig: Structured oLLM configuration instance
        
    Raises:
        ImportError: If OLLMConfig is not available
    """
    if OLLMConfig is None:
        raise ImportError("OLLMConfig not available. Please ensure config_utils.py is accessible.")
    
    # Get base configuration and model-specific overrides
    base_config = OLLM_CONFIG.copy()
    override_config = OLLM_MODEL_OVERRIDES.get(model_name, {})
    
    # Use merge function if available, otherwise manual merge
    if merge_ollm_configs is not None:
        return merge_ollm_configs(base_config, override_config)
    else:
        # Fallback manual merge
        merged_config = base_config.copy()
        merged_config.update(override_config)
        return OLLMConfig.from_dict(merged_config)

# Ensure directories exist
os.makedirs(GENERATED_CODE_DIR, exist_ok=True)
os.makedirs(AEP_DIR, exist_ok=True)
os.makedirs(EXPLOITED_CODE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)